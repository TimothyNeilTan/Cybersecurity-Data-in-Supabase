// Purpose: Extracts node URIs and relationships from CWE JSON data
export default class cweFunctions {
    constructor() {};
    cweDataExtract(jsonData: any) {
        const cweData: {created_at: Date, schema: string, node_type: string, data_type: string, version: string, provider: string, node_data: any[], cweID: string}[] = [];        

        for (const items of jsonData.Weakness_Catalog.Weaknesses[0].Weakness) {
            // let cweOverall = [];
            let cweDescription = [];
            let ModesOfIntroduction = [];
            let Modifications = [];
            let Notes = [];
            let Affected_Resources = [];
            let Functional_Areas = [];

            if (items.Modes_Of_Introduction){
                for (const vars of items.Modes_Of_Introduction[0].Introduction) {
                for (const phase of vars.Phase)
                    ModesOfIntroduction.push({Phase: phase.toString()})
            }}
            else {
                ModesOfIntroduction.push({Phase: "No phases."})
            };

            if (items.Content_History && items.Content_History[0].Modification) {
                for (const vars of items.Content_History[0].Modification) {
                    Modifications.push({
                        Modification_Name: vars.Modification_Name,
                        Modification_Organization: vars.Modification_Organization,
                        Modification_Date: vars.Modification_Date,
                        Modification_Comment: vars.Modification_Comment})
            }}
            else {
                Modifications.push({Modifications: "No Modifications."})
            };

            if (items.Notes) {
                for (const vars of items.Notes[0].Note) {
                Notes.push({
                    Note: vars._,
                    NoteType: vars.$.Type})
            }}
            else {Notes.push({Notes: "No notes"})};

            if (items.Affected_Resources) {
                for (const vars of items.Affected_Resources[0].Affected_Resource) {
                Affected_Resources.push({Affected_Resources: vars.toString()})
            }}
            else {Affected_Resources.push({Affected_Resources: "No Affected Resources"})};


            if (items.Functional_Areas){
                for (const vars of items.Functional_Areas[0].Functional_Area) {
                Functional_Areas.push({Functional_Areas: vars.toString()})
            }}
            else {Functional_Areas.push({Functional_Areas: "No Functional Areas"})};

            cweDescription.push({
                cweID: ("CWE-" + items.$.ID),
                Name: items.$.Name,
                Abstraction: items.$.Abstraction,
                Structure: items.$.Structure,
                Status: items.$.Status,
                Description: items.Description,
                ExtendedDescription:
                  typeof items.Extended_Description === "string"
                    ? items.Extended_Description.toString()
                    : typeof items.Extended_Description === "object" &&
                      items.Extended_Description !== null &&
                      "xhtml:p" in items.Extended_Description
                    ? items.Extended_Description["xhtml:p"].toString()
                    : null,
                LikelihoodOfExploit: items.Likelihood_Of_Exploit,
                BackgroundDetails: items.Background_Details?.[0]?.Background_Detail?.toString() || null,
                ModesOfIntroduction: ModesOfIntroduction,
                SubmissionDate: items.Content_History[0].Submission[0].Submission_Date,
                SubmissionName: items.Content_History[0].Submission[0].Submission_Name,
                SubmissionOrganization: items.Content_History[0].Submission[0].Submission_Organization,
                Modifications: Modifications,
                AlternateTerms: items.Alternate_Terms?.toString() || null,
                Notes: Notes,
                AffectedResources: Affected_Resources,
                FunctionalAreas: Functional_Areas
              });

            cweData.push({
                // node_uuid: uuidv4(),
                created_at: new Date(),
                provider: "CWE",
                schema: "@asgs/schemas/cwe.json",
                version: "1.0",
                node_type: "CWE",
                data_type: "cwe",
                node_data: cweDescription,
                cweID: ("CWE-" + items.$.ID),
            });
        }
        return cweData};

    cweCategoryDataExtract(jsonData: any) {
        const cweData: {created_at: Date, schema: string, node_type: string, data_type: string, version: string, provider: string, node_data: any[], cweID: string}[] = [];
        for (const items of jsonData.Categories.Category[0]) {
            let cweDescription = [];
            let Modifications = [];
            let Notes = [];

            if (items.Content_History && items.Content_History[0].Modification) {
                for (const vars of items.Content_History[0].Modification) {
                    Modifications.push({
                        Modification_Name: vars.Modification_Name,
                        Modification_Organization: vars.Modification_Organization,
                        Modification_Date: vars.Modification_Date,
                        Modification_Comment: vars.Modification_Comment})
            }}
            else {
                Modifications.push({Modifications: "No Modifications."})
            };

            if (items.MappingNotes[0]) {
                Notes.push({
                    Usage: items.MappingNotes[0].Usage,
                    Rationale: items.MappingNotes[0].Rationale,
                    Comments: items.MappingNotes[0].Comments
                //to add reason portion after
                })
            }
            else {Notes.push({Notes: "No notes"})};

            cweDescription.push({
                cweID: ("CWE-" + items.$.ID),
                Name: items.$.Name,
                Status: items.$.Status,
                Summary: items.Summary,
                Notes: Notes,
                Description: items.Description,
                SubmissionDate: items.Content_History[0].Submission[0].Submission_Date,
                SubmissionName: items.Content_History[0].Submission[0].Submission_Name,
                SubmissionOrganization: items.Content_History[0].Submission[0].Submission_Organization,
                Modifications: Modifications
              });

            cweData.push({
                // node_uuid: uuidv4(),
                created_at: new Date(),
                provider: "CWE",
                schema: "@asgs/schemas/cwe.json",
                version: "1.0",
                node_type: "CWE",
                data_type: "cwe",
                node_data: cweDescription,
                cweID: ("CWE-" + items.$.ID),
            });
        }
        return cweData};


}
