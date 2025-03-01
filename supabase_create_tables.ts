import { node_type } from './enum_sql_queries';
import { exec } from 'child_process';

interface TableQueries {
  [key: string]: string;
}

const supabaseQueries: TableQueries = {
    CWE: node_type.CWE,
    CPE: node_type.CPE,
    CVE: node_type.CVE,
  };

function runSupabaseQuery(name: string, query: string): void {
    // Replace newlines with spaces for command-line execution.
    const command = `supabase db query "${query.replace(/\n/g, ' ')}"`;
    console.log(`Executing query for ${name} table...`);
  
    exec(command, (error, stdout, stderr) => {
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