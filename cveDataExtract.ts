// Purpose: Extracts node URIs and relationships from CVE JSON data

export default class cveFunctions {
    constructor() {}

    cveDataExtract(jsonData: any) {
        // console.log(jsonData);
        // const cveJsonData: {cveId: string, assigner: string, description: string, published_date: string, last_modified_date: string}[] = [];
        const cveData: {created_at: Date, schema: string, node_type: string, data_type: string, provider: string, cveID: string, node_data: any[]}[] = [];
        for (const items of jsonData.CVE_Items) {
            let cveJsonData = [];
            // console.log(items);
            // Collect the parent URI
            const englishDescription = items.cve.description.description_data.find((desc: any) => desc.lang === "en");

            cveJsonData.push({
                cveId: items.cve.CVE_data_meta.ID,
                assigner: items.cve.CVE_data_meta.ASSIGNER,
                description: englishDescription ? englishDescription: items.cve.description.description_data.desc.value,
                published_date: items.publishedDate,
                last_modified_date: items.lastModifiedDate
            });
            cveData.push({
                created_at: new Date(),
                provider: "CVE",
                schema: "@asgs/schemas/cve.json",
                node_type: "CVE",
                data_type: "cve",
                cveID: items.cve.CVE_data_meta.ID,
                node_data: cveJsonData});
            };
            console.log(cveData);
        return cveData};


    cveRelationshipsExtract(jsonData: any){
        const fs = require('fs');
        // const { v4: uuidv4 } = require('uuid');
        const path = require('path');
        const relationships: {created_at: Date, source_node: any, target_node: any, relationship_type: string, relationship_data: any[]}[] = [];

        //---------------for readability----------------///
        const cveBatchData = JSON.parse(fs.readFileSync(path.join(__dirname, '..' ,'dataStorage', 'CVE_batch.json'), 'utf8'));
        interface cveEntry {
            cveID: string;
            node_uuid: string;
          }
        const cveBatchIndex = new Map<string, cveEntry>(
        (cveBatchData as cveEntry[])
            .filter((entry: cveEntry) => entry !== null)
            .map((entry: cveEntry) => [entry.cveID, entry])
        );
        ;

        //---------------for readability----------------///
        const cpeBatchData = JSON.parse(fs.readFileSync(path.join(__dirname, '..' ,'dataStorage', 'CPE_batch.json'), 'utf8'));
        interface cpeEntry {
            cpeID: string;
            node_uuid: string;
          }
        // const cpeBatchIndex = new Map<string, cpeEntry>(
        // (cpeBatchData as cpeEntry[]).map((entry: cpeEntry) => [entry.cpeID, entry])
        // )
        const cpeBatchIndex = new Map<string, cpeEntry>(
            (cpeBatchData as cpeEntry[])
              .filter((entry: cpeEntry) => entry !== null)
              .map((entry: cpeEntry) => [entry.cpeID, entry])
          );
          
        
        ;

        //---------------for readability----------------///
        const cweBatchData = JSON.parse(fs.readFileSync(path.join(__dirname, '..','dataStorage', 'CWE_batch.json'), 'utf8'));
        interface cweEntry {
            cweID: string;
            node_uuid: string;
          }
        const cweBatchIndex = new Map<string, cweEntry>(
            (cweBatchData as cweEntry[])
              .filter((entry: cweEntry) => entry !== null)
              .map((entry: cweEntry) => [entry.cweID, entry])
          );
          
        

        for (const items of jsonData.CVE_Items) {
            for (const node of items.configurations.nodes) {
                for (const child of node.children) {
                    for (const cpeValue of child.cpe_match) {
                        let cpe_relationships_json = [];
                        cpe_relationships_json.push({
                            source_node: cveBatchIndex.get(items.cve.CVE_data_meta.ID)?.node_uuid,
                            target_node: cpeBatchIndex.get(cpeValue.cpe23Uri)?.node_uuid,
                            relationship_type: "VulnerableTo",
                            created_at: new Date()
                        })
                        relationships.push({
                            created_at: new Date(),
                            source_node: cpeBatchIndex.get(items.cve.CVE_data_meta.ID)?.node_uuid,
                            target_node: cpeBatchIndex.get(cpeValue.cpe23Uri)?.node_uuid,
                            relationship_type: "VulnerableTo",
                            relationship_data: cpe_relationships_json,
                        })
                    }
                }};
        
            for (const problemtype of items.cve.problemtype.problemtype_data) {
                for (const CWE of problemtype.description) {
                    let cwe_relationships_json = [];
                    cwe_relationships_json.push({
                        source_node: cveBatchIndex.get(items.cve.CVE_data_meta.ID)?.node_uuid,
                        target_node: cveBatchIndex.get(CWE.value)?.node_uuid,
                        relationship_type: "Problem_Type",
                        created_at: new Date()
                    })
                    relationships.push({
                        created_at: new Date(),
                        source_node: cveBatchIndex.get(items.cve.CVE_data_meta.ID)?.node_uuid,
                        target_node: cweBatchIndex.get(CWE.value)?.node_uuid,
                        relationship_type: "Problem_Type",
                        relationship_data: cwe_relationships_json,
                    })
                }
            }}
        return relationships};
    }