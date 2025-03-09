// Purpose: Extracts node URIs and relationships from CWE JSON data
export default class cweFunctions {
    constructor() {};
    cweDataExtract(jsonData: any) {
        const { v4: uuidv4 } = require('uuid');
        const cweData: {node_uuid: string, created_at: Date, schema: string, node_type: string, data_type: string, version: string, provider: string, node_data: any[], cweID: string}[] = [];        
        let submissionName: string;
        let submissionDate: string;
        let submissionOrganization: string;

        for (const items of jsonData.Weakness_Catalog.Views[0].View) {
            let cweOverall = [];
            let cweModifications = [];
            let cweStakeholders = [];
            let cweMembers = [];
            let cwePublicReferences = [];
            if (items.Content_History && items.Content_History[0].Submission) {
                submissionName = items.Content_History[0].Submission[0].Submission_Name;
                submissionDate = items.Content_History[0].Submission[0].Submission_Date;
                submissionOrganization = items.Content_History[0].Submission[0].Submission_Organization;
                cweModifications.push({modification: items.Content_History[0].Modification});
            } else {
                submissionName = "No submission name available";
                submissionDate = "No submission date available";
                submissionOrganization = "No submission organization available";
                cweModifications.push({modification: ["No modifications available"]}
                );
            };
            if (items.Audience) {
                for (const stakeholder of items.Audience[0].Stakeholder) {
                    cweStakeholders.push(
                        {stakeholder: stakeholder.Type, 
                        stakeholder_description: stakeholder.Description}
                    );
                };
            } else {
                cweStakeholders.push(
                    {stakeholder: "No stakeholders available",
                    stakeholder_description: "No stakeholders available"}
                );
            };
            if (items.Members) {
                for (const member of items.Members[0].Has_Member) {
                    cweMembers.push(
                        {member: member.$.CWE_ID}
                    );
                };
            } else {
                cweMembers.push(
                    {member: "No members available"}
                );
            };
            if (items.Reference && 
                Array.isArray(items.Reference) &&
                items.References[0].Reference &&
                items.References[0].Reference.$ &&
                items.References[0].Reference.$.External_Reference_ID
              ) {
                for (const reference of items.References[0].Reference) {
                    cwePublicReferences.push(
                        {publicReference: reference.$.External_Reference_ID}
                    );
                };
            } else {
                cwePublicReferences.push(
                    {publicReference: "No references available"}
                );
            };
            cweOverall.push({
                cweID: ("CWE-" + items.$.ID),
                name: items.$.Name,
                type: items.$.Type,
                status: items.$.Status,
                objective: JSON.stringify(items.Objective),
                filter: items.Filter,
                notes: JSON.stringify(items.Notes),
                submission_name: submissionName,
                submission_date: submissionDate,
                submission_organization: submissionOrganization,
                modifications: cweModifications,
                stakeholders: cweStakeholders,
                members: cweMembers,
                references: cwePublicReferences
            });
            cweData.push({
                node_uuid: uuidv4(),
                created_at: new Date(),
                provider: "CWE",
                schema: "@asgs/schemas/cwe.json",
                version: "1.0",
                node_type: "CWE",
                data_type: "cwe",
                node_data: cweOverall,
                cweID: ("CWE-" + items.$.ID),
            });
        }
        return cweData};
}