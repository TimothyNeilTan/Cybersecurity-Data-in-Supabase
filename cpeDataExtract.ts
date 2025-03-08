// Purpose: Extracts node URIs and relationships from CPE JSON data


export default class cpeFunctions {
    
    constructor(){}
    cpeDataExtract(jsonData: any) {
        const { v4: uuidv4 } = require('uuid');
        const cpeData: {node_uuid: string, created_at: Date, schema: string, provider: string, node_type: string, data_type: string, cpeID: string, node_data: any[]}[] = [];
        for (const items of jsonData) {
            let cpeJsonData = [];
            // Collect the parent URI
            cpeJsonData.push({
                cpeUri: items.cpe23Uri
            });

            cpeData.push({
                node_uuid: uuidv4(),
                created_at: new Date(),
                schema: "@asgs/schemas/cpe.json",
                node_type: "CPE",
                data_type: "cpe",
                provider: "CPE",
                cpeID: items.cpe23Uri,
                node_data: cpeJsonData});
            }
        return cpeData};

    cpeRelationshipsExtract(jsonData: any){
        const { v4: uuidv4 } = require('uuid');
        const fs = require('fs');
        const path = require('path');
        const cpeBatchData = JSON.parse(fs.readFileSync(path.join(__dirname, 'dataStorage', 'CPE_Batch.json'), 'utf8'));
        const relationships: {relationship_uuid: string, created_at: Date, source_node: string, target_node: string, relationship_type: string, relationship_data: any[]}[] = [];
        interface cpeEntry {
            cpeID: string;
            node_uuid: string;
          }
        const cpeBatchIndex = new Map<string, cpeEntry>(
        (cpeBatchData as cpeEntry[]).map((entry: cpeEntry) => [entry.cpeID, entry])
        );
        for (const items of jsonData) {
            let cpe_relationships_json = [];
            // If there are children, create a relationship record for each
            for (const items_child of items.cpe_name) {
                cpe_relationships_json.push({ 
                    source_node: items.cpe23Uri,
                    target_node: items_child.cpe23Uri,
                    relationshipType: "parentOf",
                    created_at: new Date()
                });

                relationships.push({
                    relationship_uuid: uuidv4(),
                    created_at: new Date(),
                    source_node: JSON.stringify(cpeBatchIndex.get(items.cpe23Uri)?.node_uuid),
                    target_node: JSON.stringify(cpeBatchIndex.get(items_child.cpe23Uri)?.node_uuid),
                    relationship_type: "PARENTOF",
                    relationship_data: cpe_relationships_json,
                });
            }
            
        } 
        return relationships};

        }