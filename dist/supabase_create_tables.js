"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const enum_sql_queries_1 = require("./enum_sql_queries");
const child_process_1 = require("child_process");
const supabaseQueries = {
    CWE: enum_sql_queries_1.node_type.CWE,
    CPE: enum_sql_queries_1.node_type.CPE,
    CVE: enum_sql_queries_1.node_type.CVE,
};
function runSupabaseQuery(name, query) {
    // Replace newlines with spaces for command-line execution.
    const command = `supabase db query "${query.replace(/\n/g, ' ')}"`;
    console.log(`Executing query for ${name} table...`);
    (0, child_process_1.exec)(command, (error, stdout, stderr) => {
        if (error) {
            console.error(`Error creating ${name} table:`, error);
            return;
        }
        if (stderr) {
            console.error(`stderr for ${name} table:`, stderr);
        }
        console.log(`Output for ${name} table: ${stdout}`);
    });
}
//   Iterate over each query and execute it.
for (const [tableName, query] of Object.entries(supabaseQueries)) {
    runSupabaseQuery(tableName, query);
}
