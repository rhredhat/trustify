use itertools::Itertools;
use sea_orm::EntityTrait;
use test_context::test_context;
use test_log::test;
use trustify_entity::{package_relates_to_package, sbom, sbom_package};
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

/// Verifies that nested components become an assembly and that component types without a table
/// of their own are still recorded.
///
/// Such a component used to be dropped, which left any relationship pointing at it dangling and
/// failed the whole document. Nested components used to be flattened without recording that the
/// parent contains them.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn ingest_assemblies(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given an SBOM of nested components, none of which is an application, library or file
    let result = ctx
        .ingest_document("cyclonedx/assemblies_1dot7.json")
        .await?;
    let sbom_id = Uuid::parse_str(&result.id)?;

    // Then every component is recorded as a package
    let packages: Vec<String> = sbom_package::Entity::find()
        .all(&ctx.db)
        .await?
        .into_iter()
        .filter(|package| package.sbom_id == sbom_id)
        .map(|package| package.node_id)
        .sorted_unstable()
        .collect();

    assert_eq!(
        packages,
        ["appliance", "bios", "blob", "board", "driver", "runtime"]
    );

    // And the nesting is recorded as `Contains`, alongside the declared dependencies
    let relationships: Vec<String> = package_relates_to_package::Entity::find()
        .all(&ctx.db)
        .await?
        .into_iter()
        .filter(|rel| rel.sbom_id == sbom_id)
        .map(|rel| {
            format!(
                "{} {} {}",
                rel.left_node_id, rel.relationship, rel.right_node_id
            )
        })
        .sorted_unstable()
        .collect();

    assert_eq!(
        relationships,
        [
            "CycloneDX-doc-ref Describes appliance",
            "appliance Dependency board",
            "appliance Dependency runtime",
            "board Contains bios",
            "board Contains driver",
            "driver Contains blob",
            "driver Dependency bios",
        ]
    );

    Ok(())
}

/// Verifies that the tools which created the document show up as authors, the way SPDX `Tool:`
/// creators do.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn ingest_tools_as_authors(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given an SBOM created by a person and a tool
    let result = ctx
        .ingest_document("cyclonedx/assemblies_1dot7.json")
        .await?;
    let sbom_id = Uuid::parse_str(&result.id)?;

    // Then both are recorded as authors
    let sbom = sbom::Entity::find_by_id(sbom_id)
        .one(&ctx.db)
        .await?
        .expect("must exist");

    assert_eq!(sbom.authors, ["Some Author", "assembler-1.2.3"]);
    assert_eq!(sbom.suppliers, ["Some Supplier"]);

    Ok(())
}
