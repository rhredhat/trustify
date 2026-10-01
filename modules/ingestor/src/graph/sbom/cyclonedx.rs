use crate::{
    graph::{
        cpe::CpeCreator,
        product::ProductInformation,
        purl::creator::PurlCreator,
        sbom::{
            CryptographicAssetCreator, CycloneDx as CycloneDxProcessor, LicenseCreator,
            LicenseInfo, LicensingInfo, LicensingInfoCreator, MachineLearningModelCreator,
            NodeInfoParam, PackageCreator, PackageLicensenInfo, PackageReference, References,
            RelationshipCreator, SbomContext, SbomInformation, populate_expanded_license,
            processor::{
                InitContext, PostContext, Processor, RedHatProductComponentRelationships,
                RunProcessors,
            },
            sbom_package_license::LicenseCategory,
        },
    },
    service::Error,
};
use base64::{Engine, prelude::BASE64_STANDARD};
use sbom_walker::{
    model::sbom::serde_cyclonedx::Sbom,
    report::{ReportSink, check},
};
use sea_orm::ConnectionTrait;
use serde_cyclonedx::cyclonedx::v_1_7::{
    Attachment, Component, ComponentEvidenceIdentity, CycloneDx, License,
    LicenseAcknowledgementEnumeration, LicenseChoice, LicenseChoiceItemUrl, MetadataTools,
    OrganizationalContact, OrganizationalEntity,
};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    str::FromStr,
};
use time::{OffsetDateTime, format_description::well_known::Iso8601};
use tracing::instrument;
use trustify_common::{advisory::cyclonedx::extract_properties_json, cpe::Cpe, purl::Purl};
use trustify_entity::relationship::Relationship;
use uuid::Uuid;

use super::FileCreator;

/// Marker we use for identifying the document itself.
///
/// Similar to the SPDX doc id, which is attached to the document itself. CycloneDX doesn't have
/// such a concept, but can still attach a component to the document via a dedicated metadata
/// component.
pub const CYCLONEDX_DOC_REF: &str = "CycloneDX-doc-ref";

pub struct Information<'a>(pub &'a CycloneDx);

fn from_contact(contact: &OrganizationalContact) -> Option<String> {
    match (&contact.name, &contact.email) {
        (Some(name), Some(email)) => Some(format!("{name} <{email}>")),
        (Some(name), None) => Some(name.to_string()),
        (None, Some(email)) => Some(email.to_string()),
        (None, None) => None,
    }
}

/// Name an organization: by name, else by its contacts, else by its URLs.
fn from_organization(organization: &OrganizationalEntity) -> Vec<String> {
    organization
        .name
        .clone()
        .map(|name| vec![name])
        .or_else(|| {
            organization
                .contact
                .as_ref()
                .map(|c| c.iter().filter_map(from_contact).collect())
        })
        .or_else(|| organization.url.clone())
        .unwrap_or_default()
}

/// Name the tools which created the document, as `name-version`.
///
/// SPDX records its tools as `Tool:` creators, alongside the people and organizations which
/// created the document. CycloneDX keeps them apart in `metadata.tools`, so we fold them into the
/// authors to end up with the same set of creators either way.
fn from_tools(tools: &MetadataTools) -> Vec<String> {
    fn label(name: &str, version: Option<&str>) -> String {
        match version {
            Some(version) => format!("{name}-{version}"),
            None => name.to_string(),
        }
    }

    match tools {
        // tools described as components and services
        MetadataTools::Variant0(tools) => tools
            .components
            .iter()
            .flatten()
            .map(|c| label(&c.name, c.version.as_deref()))
            .chain(
                tools
                    .services
                    .iter()
                    .flatten()
                    .map(|s| label(&s.name, s.version.as_deref())),
            )
            .collect(),
        // the legacy, flat list of tools
        MetadataTools::Variant1(tools) => tools
            .iter()
            .filter_map(|tool| Some(label(tool.name.as_deref()?, tool.version.as_deref())))
            .collect(),
    }
}

/// Drop duplicates, keeping the first occurrence.
fn dedup(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

/// Map a CycloneDX license acknowledgement onto the category we store it under.
///
/// The acknowledgement is optional; `default` is what the containing field implies when it is
/// absent.
fn license_category(
    acknowledgement: Option<&LicenseAcknowledgementEnumeration>,
    default: LicenseCategory,
) -> LicenseCategory {
    match acknowledgement {
        Some(LicenseAcknowledgementEnumeration::Declared) => LicenseCategory::Declared,
        Some(LicenseAcknowledgementEnumeration::Concluded) => LicenseCategory::Concluded,
        None => default,
    }
}

/// Extract the textual content of a license attachment, decoding it if necessary.
///
/// `base64` is the only encoding CycloneDX defines; anything else is taken verbatim.
fn license_text(text: &Attachment) -> Option<String> {
    match text.encoding.as_deref() {
        Some("base64") => match BASE64_STANDARD.decode(&text.content) {
            Ok(decoded) => String::from_utf8(decoded)
                .inspect_err(|err| log::info!("Skipping non-UTF-8 license text: {err}"))
                .ok(),
            Err(err) => {
                log::info!("Skipping license text which failed to base64-decode: {err}");
                None
            }
        },
        _ => Some(text.content.clone()),
    }
}

impl<'a> From<Information<'a>> for SbomInformation {
    fn from(value: Information<'a>) -> Self {
        let sbom = value.0;

        let published = sbom
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.timestamp.as_ref())
            .and_then(|timestamp| {
                OffsetDateTime::parse(timestamp.as_ref(), &Iso8601::DEFAULT).ok()
            });

        // authors: the people who created the document, plus the tools which did

        let authors = dedup(
            sbom.metadata
                .as_ref()
                .and_then(|metadata| metadata.authors.as_ref())
                .into_iter()
                .flatten()
                .filter_map(from_contact)
                .chain(
                    sbom.metadata
                        .as_ref()
                        .and_then(|metadata| metadata.tools.as_ref())
                        .into_iter()
                        .flat_map(from_tools),
                ),
        );

        // suppliers: of the document, and of the component it describes
        //
        // SPDX only knows the latter, as it collects the suppliers of the packages describing the
        // document. In CycloneDX that is `metadata.component`.

        let suppliers = dedup(
            sbom.metadata
                .as_ref()
                .into_iter()
                .flat_map(|metadata| {
                    metadata.supplier.iter().chain(
                        metadata
                            .component
                            .as_ref()
                            .and_then(|component| component.supplier.as_ref()),
                    )
                })
                .flat_map(from_organization),
        );

        let name = sbom
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.component.as_ref())
            .map(|component| component.name.to_string())
            // otherwise use the serial number
            .or_else(|| sbom.serial_number.as_ref().map(|id| id.to_string()))
            // TODO: not sure what to use instead, the version will most likely be `1`.
            .or_else(|| sbom.version.as_ref().map(|v| v.to_string()))
            .unwrap_or_else(|| "<unknown>".to_string());

        let data_licenses = sbom
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.licenses.as_ref())
            .into_iter()
            .flatten()
            .filter_map(|license| match license {
                LicenseChoiceItemUrl::Variant0(l) => {
                    l.license.id.as_ref().or(l.license.name.as_ref()).cloned()
                }
                LicenseChoiceItemUrl::Variant1(l) => Some(l.expression.clone()),
            })
            .collect();

        Self {
            node_id: CYCLONEDX_DOC_REF.to_string(),
            name,
            published,
            authors,
            suppliers,
            data_licenses,
            properties: extract_properties_json(sbom),
        }
    }
}

impl SbomContext {
    #[instrument(skip(connection, sbom, warnings), err(level=tracing::Level::INFO))]
    pub async fn ingest_cyclonedx(
        &self,
        mut sbom: Box<CycloneDx>,
        warnings: &dyn ReportSink,
        connection: &impl ConnectionTrait,
    ) -> Result<(), Error> {
        // pre-flight checks

        check::serde_cyclonedx::all(warnings, &Sbom::V1_7(Cow::Borrowed(&sbom)));

        let mut creator = Creator::new(self.sbom.sbom_id);

        // TODO: find a way to dynamically set up processors
        let mut processors: Vec<Box<dyn Processor>> =
            vec![Box::new(RedHatProductComponentRelationships::new())];

        // init processors

        let suppliers = sbom
            .metadata
            .as_ref()
            .and_then(|m| m.supplier.as_ref().and_then(|org| org.name.as_deref()))
            .into_iter()
            .collect::<Vec<_>>();
        InitContext {
            document_node_id: CYCLONEDX_DOC_REF,
            suppliers: &suppliers,
        }
        .run(&mut processors);

        // extract "describes"

        if let Some(metadata) = &mut sbom.metadata
            && let Some(component) = &mut metadata.component
        {
            let bom_ref = component
                .bom_ref
                .get_or_insert_with(|| Uuid::new_v4().to_string())
                .to_string();

            let product_cpe = component
                .cpe
                .as_ref()
                .map(|cpe| Cpe::from_str(cpe.as_ref()))
                .transpose()
                .map_err(|err| Error::InvalidContent(err.into()))?;
            let pr = self
                .graph
                .ingest_product(
                    component.name.clone(),
                    ProductInformation {
                        vendor: component.publisher.clone(),
                        cpe: product_cpe,
                    },
                    connection,
                )
                .await?;

            if let Some(ver) = component.version.clone() {
                pr.ingest_product_version(ver.to_string(), Some(self.sbom.sbom_id), connection)
                    .await?;
            }

            // create component

            creator.add(component);

            // create a relationship

            creator.relate(
                CYCLONEDX_DOC_REF.to_string(),
                Relationship::Describes,
                bom_ref,
            );
        }

        // record components

        creator.add_all(&sbom.components);

        // create relationships

        for left in sbom.dependencies.iter().flatten() {
            for target in left.depends_on.iter().flatten() {
                log::debug!("Adding dependency - left: {}, right: {}", left.ref_, target);
                creator.relate(left.ref_.clone(), Relationship::Dependency, target.clone());
            }

            // https://github.com/guacsec/trustify/issues/1131
            // Do we need to qualify this so that only "arch=src" refs
            // get the GeneratedFrom relationship?
            for target in left.provides.iter().flatten() {
                log::debug!("Adding generates - left: {}, right: {}", left.ref_, target);
                creator.relate(left.ref_.clone(), Relationship::Generates, target.clone());
            }
        }

        // create

        creator.create(connection, &mut processors).await?;

        self.populate_describing_cpes(connection).await?;
        self.populate_ancestors(connection).await?;

        // done

        Ok(())
    }
}

/// Creator of CycloneDX components and dependencies
#[derive(Debug, Default)]
struct Creator<'a> {
    sbom_id: Uuid,
    components: Vec<&'a Component>,
    relations: Vec<(String, Relationship, String)>,
}

impl<'a> Creator<'a> {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            components: Default::default(),
            relations: Default::default(),
        }
    }

    pub fn add_all(&mut self, components: &'a Option<Vec<Component>>) {
        self.components.extend(components.iter().flatten())
    }

    /// Record a component.
    ///
    /// Components nested inside it are picked up by [`ComponentCreator::add_component`], which
    /// also relates them to this one.
    pub fn add(&mut self, component: &'a Component) {
        self.components.push(component);
    }

    pub fn relate(&mut self, left: String, rel: Relationship, right: String) {
        self.relations.push((left, rel, right));
    }

    #[instrument(skip(self, db, processors), err(level=tracing::Level::INFO))]
    pub async fn create(
        self,
        db: &impl ConnectionTrait,
        processors: &mut [Box<dyn Processor>],
    ) -> Result<(), Error> {
        let mut creator = ComponentCreator::new(self.sbom_id, self.components.len());

        for comp in self.components {
            let _ = creator.add_component(comp)?;
        }

        for (left, rel, right) in self.relations {
            creator.add_relation(left, rel, right);
        }

        // post process
        creator.post_process(processors);

        // validate relationships before inserting
        creator.validate()?;

        // write to db
        creator.create(db).await?;

        // done

        Ok(())
    }
}

struct ComponentCreator {
    sbom_id: Uuid,
    cpes: CpeCreator,
    purls: PurlCreator,
    licenses: LicenseCreator,
    licensing_infos: LicensingInfoCreator,
    packages: PackageCreator,
    files: FileCreator,
    models: MachineLearningModelCreator,
    crypto: CryptographicAssetCreator,
    relationships: RelationshipCreator<CycloneDxProcessor>,
    // Map each node to a collection of references
    refs: HashMap<String, Vec<PackageReference>>,
}

impl ComponentCreator {
    pub fn new(sbom_id: Uuid, capacity: usize) -> Self {
        Self {
            sbom_id,
            cpes: CpeCreator::new(),
            purls: PurlCreator::new(),
            licenses: LicenseCreator::new(),
            licensing_infos: LicensingInfoCreator::new(),
            packages: PackageCreator::with_capacity(sbom_id, capacity),
            files: FileCreator::new(sbom_id),
            models: MachineLearningModelCreator::new(sbom_id),
            crypto: CryptographicAssetCreator::new(sbom_id),
            relationships: RelationshipCreator::new(sbom_id, CycloneDxProcessor),
            refs: Default::default(),
        }
    }

    /// Record a component, everything nested inside it, and its pedigree.
    ///
    /// Returns the node id the component was recorded under, which is its `bom-ref` unless it
    /// doesn't have one.
    pub fn add_component(&mut self, comp: &Component) -> Result<String, Error> {
        let node_id = comp
            .bom_ref
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let licenses = self.add_license(comp);

        if let Some(cpe) = &comp.cpe {
            match Cpe::from_str(cpe.as_ref()) {
                Ok(cpe) => {
                    self.add_cpe(node_id.clone(), cpe);
                }
                Err(err) => {
                    log::info!("Skipping CPE due to parsing error: {err}");
                }
            }
        }

        if let Some(purl) = &comp.purl {
            match Purl::from_str(purl.as_ref()) {
                Ok(purl) => {
                    self.add_purl(node_id.clone(), purl);
                }
                Err(err) => {
                    log::info!("Skipping PURL due to parsing error: {err}");
                }
            }
        }

        for identity in comp
            .evidence
            .as_ref()
            .and_then(|evidence| evidence.identity.as_ref())
            .iter()
            .flat_map(|id| match id {
                ComponentEvidenceIdentity::Variant0(value) => value.iter().collect::<Vec<_>>(),
                ComponentEvidenceIdentity::Variant1(value) => vec![value],
            })
        {
            match (identity.field.as_str(), &identity.concluded_value) {
                ("cpe", Some(cpe)) => {
                    if let Ok(cpe) = Cpe::from_str(cpe.as_ref()) {
                        self.add_cpe(node_id.clone(), cpe);
                    }
                }
                ("purl", Some(purl)) => {
                    if let Ok(purl) = Purl::from_str(purl.as_ref()) {
                        self.add_purl(node_id.clone(), purl);
                    }
                }

                _ => {}
            }
        }

        match ComponentType::from_str(&comp.type_) {
            Ok(ty) => {
                use ComponentType::*;
                const EMPTY: Vec<PackageReference> = vec![];
                match ty {
                    File => {
                        self.files.add(
                            node_id.clone(),
                            comp.name.to_string(),
                            comp.hashes.clone().into_iter().flatten(),
                        );
                    }
                    MachineLearningModel => {
                        self.models.add(
                            node_id.clone(),
                            comp.name.to_string(),
                            self.refs.get(&node_id).unwrap_or(&EMPTY).iter(),
                            comp.hashes.clone().into_iter().flatten(),
                            comp.into(),
                        );
                    }
                    CryptographicAsset => {
                        self.crypto.add(
                            node_id.clone(),
                            comp.name.to_string(),
                            comp.hashes.clone().into_iter().flatten(),
                            comp.try_into()?,
                        );
                    }
                    // Everything else becomes a "package". Types like `device` or `firmware`
                    // have no table of their own, but dropping them would leave the
                    // relationships pointing at them dangling, failing the whole document.
                    _ => self.packages.add(
                        NodeInfoParam {
                            node_id: node_id.clone(),
                            name: comp.name.to_string(),
                            group: comp.group.as_ref().map(|v| v.to_string()),
                            version: comp.version.as_ref().map(|v| v.to_string()),
                            package_license_info: licenses,
                        },
                        self.refs.get(&node_id).unwrap_or(&EMPTY).iter(),
                        comp.hashes.clone().into_iter().flatten(),
                    ),
                }
            }
            Err(e) => {
                return Err(Error::InvalidContent(anyhow::anyhow!(
                    "Invalid component type: {e}"
                )));
            }
        }

        // Nested components are an assembly: the component is made up of its parts. That is the
        // same idea as an SPDX `CONTAINS` relationship, and unrelated to dependencies.

        for nested in comp.components.iter().flatten() {
            let target = self.add_component(nested)?;

            self.add_relation(node_id.clone(), Relationship::Contains, target);
        }

        for ancestor in comp
            .pedigree
            .iter()
            .flat_map(|pedigree| pedigree.ancestors.iter().flatten())
        {
            let target = self.add_component(ancestor)?;

            self.add_relation(target, Relationship::AncestorOf, node_id.clone());
        }

        for variant in comp
            .pedigree
            .iter()
            .flat_map(|pedigree| pedigree.variants.iter().flatten())
        {
            let target = self.add_component(variant)?;

            self.add_relation(node_id.clone(), Relationship::Variant, target);
        }

        Ok(node_id)
    }

    fn add_relation(&mut self, left: String, rel: Relationship, right: String) {
        self.relationships.relate(left, rel, right);
    }

    fn add_cpe(&mut self, node_id: String, cpe: Cpe) {
        let id = cpe.uuid();
        self.refs
            .entry(node_id)
            .or_default()
            .push(PackageReference::Cpe(id));
        self.cpes.add(cpe);
    }

    fn add_purl(&mut self, node_id: String, purl: Purl) {
        self.refs
            .entry(node_id)
            .or_default()
            .push(PackageReference::Purl(purl.clone()));
        self.purls.add(purl);
    }

    /// Collect the licenses of a component, split into declared and concluded ones.
    fn add_license(&mut self, component: &Component) -> Vec<PackageLicensenInfo> {
        let mut result = vec![];

        // The licenses asserted for the component. An item may say whether that assertion is
        // declared or concluded; when it doesn't, we keep treating it as declared.
        self.add_licenses(
            component.licenses.as_ref(),
            LicenseCategory::Declared,
            &mut result,
        );

        // The licenses observed while analysing the component. Being the outcome of an analysis,
        // they are what SPDX calls a concluded license.
        self.add_licenses(
            component
                .evidence
                .as_ref()
                .and_then(|evidence| evidence.licenses.as_ref()),
            LicenseCategory::Concluded,
            &mut result,
        );

        result
    }

    fn add_licenses(
        &mut self,
        licenses: Option<&LicenseChoice>,
        default: LicenseCategory,
        result: &mut Vec<PackageLicensenInfo>,
    ) {
        for license in licenses.into_iter().flatten() {
            let (license, acknowledgement) = match license {
                LicenseChoiceItemUrl::Variant0(license) => {
                    self.add_licensing_info(&license.license);

                    let Some(name) = license
                        .license
                        .id
                        .clone()
                        .or_else(|| license.license.name.clone())
                    else {
                        continue;
                    };
                    (name, license.license.acknowledgement.as_ref())
                }
                LicenseChoiceItemUrl::Variant1(license) => {
                    (license.expression.clone(), license.acknowledgement.as_ref())
                }
            };

            let license = LicenseInfo { license };
            let info = PackageLicensenInfo {
                license_id: license.uuid(),
                license_type: license_category(acknowledgement, default),
            };

            // the same license may be listed more than once under the same category
            if result
                .iter()
                .any(|l| l.license_id == info.license_id && l.license_type == info.license_type)
            {
                continue;
            }

            self.licenses.add(&license);
            result.push(info);
        }
    }

    /// Record a license's extended details (name, text, URL) in `licensing_infos`, so that
    /// license expressions referring to it can be expanded later on.
    ///
    /// Licenses with a BOM-internal identifier or a name are recorded: a plain SPDX `id` is
    /// already self-describing and needs no mapping.
    fn add_licensing_info(&mut self, license: &License) {
        let Some(license_id) = license.bom_ref.as_ref().or(license.name.as_ref()) else {
            return;
        };

        self.licensing_infos.add(&LicensingInfo::with_sbom_id(
            self.sbom_id,
            license.name.clone().unwrap_or_else(|| license_id.clone()),
            license_id.clone(),
            license
                .text
                .as_ref()
                .and_then(license_text)
                .unwrap_or_default(),
            license.url.clone(),
        ));
    }

    fn post_process(&mut self, processors: &mut [Box<dyn Processor>]) {
        PostContext {
            cpes: &self.cpes,
            purls: &self.purls,
            packages: &mut self.packages,
            relationships: &mut self.relationships.rels,
            externals: &mut self.relationships.externals,
        }
        .run(processors);
    }

    fn validate(&self) -> Result<(), Error> {
        let sources = References::new()
            .add_source(&[CYCLONEDX_DOC_REF])
            .add_source(&self.packages)
            .add_source(&self.files)
            .add_source(&self.models)
            .add_source(&self.crypto);
        self.relationships
            .validate(sources)
            .map_err(Error::InvalidContent)
    }

    // order matters to prevent cross-table deadlocks when running
    // concurrent SBOM ingestions. All SBOM loaders must use the same
    // table insertion order.
    async fn create(self, db: &impl ConnectionTrait) -> Result<(), Error> {
        self.licensing_infos.create(db).await?;
        self.licenses.create(db).await?;
        self.purls.create(db).await?;
        self.cpes.create(db).await?;
        self.packages.create(db).await?;
        self.files.create(db).await?;
        self.models.create(db).await?;
        self.crypto.create(db).await?;
        self.relationships.create(db).await?;

        // Populate expanded license tables
        populate_expanded_license(self.sbom_id, db).await?;

        Ok(())
    }
}

/// Type of the components within an SBOM, mostly based on
/// https://cyclonedx.org/docs/1.6/json/#components_items_type
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    strum::EnumString,
    strum::Display,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
pub enum ComponentType {
    /// A software application
    Application,
    /// A software framework
    Framework,
    /// A software library
    Library,
    /// A packaging and/or runtime format
    Container,
    /// A runtime environment which interprets or executes software
    Platform,
    /// A software operating system without regard to deployment model
    OperatingSystem,
    /// A hardware device such as a processor or chip-set
    Device,
    /// A special type of software that operates or controls a particular type of device
    DeviceDriver,
    /// A special type of software that provides low-level control over a device's hardware
    Firmware,
    /// A computer file
    File,
    /// A model based on training data that can make predictions or decisions without being explicitly programmed to do so
    MachineLearningModel,
    /// A collection of discrete values that convey information
    Data,
    /// A cryptographic asset including algorithms, protocols, certificates, keys, tokens, and secrets
    CryptographicAsset,
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;
    use std::str::FromStr;
    use test_log::test;

    #[test]
    fn component_types() {
        use ComponentType::*;

        // The standard conversions
        for (s, t) in [
            ("application", Application),
            ("framework", Framework),
            ("library", Library),
            ("container", Container),
            ("platform", Platform),
            ("operating-system", OperatingSystem),
            ("device", Device),
            ("device-driver", DeviceDriver),
            ("firmware", Firmware),
            ("file", File),
            ("machine-learning-model", MachineLearningModel),
            ("data", Data),
            ("cryptographic-asset", CryptographicAsset),
        ] {
            assert_eq!(ComponentType::from_str(s), Ok(t));
            assert_eq!(t.to_string(), s);
            assert_eq!(json!(t), json!(s));
        }

        // Error handling
        assert!(ComponentType::from_str("missing").is_err());
        assert_eq!(ComponentType::from_str("FiLe"), Ok(File));
    }
}
