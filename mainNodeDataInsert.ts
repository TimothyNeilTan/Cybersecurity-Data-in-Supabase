import { promises as fs } from 'fs';
import * as path from 'path';
import supabaseClient from './supabase_config';
import format from 'pg-format';
import { data } from 'cheerio/dist/commonjs/api/attributes';
import cpeFunctions from './cpeDataExtract';
import cveFunctions from './cveDataExtract';
import cweFunctions from './cweDataExtract';

export default class dataInserter {
    supabase = supabaseClient;
    importPath: string;

    constructor(supabase = supabaseClient) {
    this.supabase = supabase;
    this.importPath = path.join(__dirname, '..', 'storageDir');
    }

    async dataInsertion(): Promise<void> {
        const differentDataTypes = 
        // if you want to generate the CVE <-> CPE relationships you can uncomment the lines 68-78
        // (granted though that it will generate 13million + new records so do it at your own risk)
        // You will need to go to the cveDataExtract and uncomment the lines in 88-106 as well
        ['CWE', 'CPE', 'CVE', 'cverelationships'];
        // ['cperelationships'];

        const BATCH_SIZE = 1000;
        for (const dataType of differentDataTypes) {
            console.log(`\nInserting ${dataType} Files to Database...`);
            let files;
            if (dataType === 'cperelationships') {
                let tempDataType = 'CPE';
                files = await this.filesToInsertData(tempDataType);
            }
            else if (dataType === 'cverelationships') {
                let tempDataType = 'CVE';
                files = await this.filesToInsertData(tempDataType);
            }
            else {
                files = await this.filesToInsertData(dataType);
            };
            // const files = await this.filesToInsertData(dataType);
            // console.log(`Files to insert: ${files}`); 
            for (const file of files) {
                console.log(file);
                console.log(dataType);
                const fullFilePath = path.join(this.importPath, file);
                let fileContent = await fs.readFile(fullFilePath, 'utf8');
                fileContent = JSON.parse(fileContent);
                // Assuming file content is newline-delimited JSON objects

                //--------CPE--------//
                if (dataType === 'CPE') {{
                    const cpeData = new cpeFunctions();
                    const cpeNodes = cpeData.cpeDataExtract(fileContent);
                    
                    try {
                        for (let i = 0; i < cpeNodes.length; i += BATCH_SIZE) {
                            const batch = cpeNodes.slice(i, i + BATCH_SIZE);
                            await this.queryDataScript(batch, 'CPE');
                            console.log(`Inserted batch ${Math.floor(i / BATCH_SIZE) + 1}`);
                        }
                    console.log('Inserted CPE data');
                    } catch (e) {
                        console.error("An error occurred with uploading the CPE files: ", e);
                    }

                    // const cpeChildNodes = cpeData.cpeChildExtract(fileContent);
                    // try {
                    //     for (let i = 0; i < cpeChildNodes.length; i += BATCH_SIZE) {
                    //         const batch = cpeChildNodes.slice(i, i + BATCH_SIZE);
                    //         await this.queryDataScript(batch, 'CPE');
                    //         console.log(`Inserted batch ${Math.floor(i / BATCH_SIZE) + 1}`);
                    //     }
                    // console.log('Inserted CPE Child data');
                    // } catch (e) {
                    //     console.error("An error occurred with uploading the CPE Child files: ", e);
                    // }
                }}

                //--------CWE--------//
                else if (dataType === 'CWE') {
                    const cweData = new cweFunctions(); 
                    const cweNodes = cweData.cweDataExtract(fileContent);        
                    try {
                            for (let i = 0; i < cweNodes.length; i += BATCH_SIZE) {
                                const batch = cweNodes.slice(i, i + BATCH_SIZE);
                                await this.queryDataScript(batch, 'CWE');
                                console.log(`Inserted batch ${Math.floor(i / BATCH_SIZE) + 1}`);
                            }
                        }
                        catch (e) {
                            console.error("An error occurred with uploading the CWE files: ", e);
                        }
                    
                    const cweCategoryNodes = cweData.cweCategoryDataExtract(fileContent);
                    try {
                        for (let i = 0; i < cweCategoryNodes.length; i += BATCH_SIZE) {
                            const batch = cweCategoryNodes.slice(i, i + BATCH_SIZE);
                            await this.queryDataScript(batch, 'CWE');
                            console.log(`Inserted batch ${Math.floor(i / BATCH_SIZE) + 1}`);
                        }
                    }
                    catch (e) {
                        console.error("An error occurred with uploading the CWE files: ", e);
                    }

                }
                
                //--------CVE--------//
                else if (dataType === 'CVE') {
                    const cveData = new cveFunctions();
                    const cveNodes = cveData.cveDataExtract(fileContent);
                    try {
                        for (let i = 0; i < cveNodes.length; i += BATCH_SIZE) {
                            const batch = cveNodes.slice(i, i + BATCH_SIZE);
                            await this.queryDataScript(batch, 'CVE');
                            console.log(`Inserted batch ${Math.floor(i / BATCH_SIZE) + 1}`);
                        }
                        console.log('Inserted CVE data');
                    }
                    catch (e) {
                        console.error("An error occurred with uploading the CVE files: ", e);
                    }
                }

                else if (dataType === 'cverelationships') {
                    const cveData = new cveFunctions();
                    let relationships = cveData.cveRelationshipsExtract(fileContent);
                    try {
                        for (let i = 0; i < relationships.length; i += BATCH_SIZE) {
                            const batch = relationships.slice(i, i + BATCH_SIZE);
                            await this.queryDataScript(batch, 'relationships');
                            console.log(`Inserted batch ${Math.floor(i / BATCH_SIZE) + 1}`);
                        }
                    }
                    catch (e) {
                        console.error("An error occurred with uploading the relationships: ", e);
                    }
                }

                else if (dataType === 'cperelationships') {
                    const cpeData = new cpeFunctions();
                    let relationships = cpeData.cpeRelationshipsExtract(fileContent);
                    try {
                        for (let i = 0; i < relationships.length; i += BATCH_SIZE) {
                            const batch = relationships.slice(i, i + BATCH_SIZE);
                            await this.queryDataScript(batch, 'relationships');
                            console.log(`Inserted batch ${Math.floor(i / BATCH_SIZE) + 1}`);
                        }
                    }
                    catch (e) {
                        console.error("An error occurred with uploading the relationships: ", e);
                    }
                }
    }}}

    // SQL Query to insert data
    async queryDataScript(file: any, dataType: string): Promise<void> {
        const startTime = Date.now();
        try {
            const { data, error } = await this.supabase
                .from(`${dataType}`)
                .upsert(file)
                .select();
                    console.log(error)
                    const storageDir = path.join(__dirname, "..", 'dataStorage');
                    const fileName = `${dataType}_batch.json`;
                    try {
                        await fs.access(path.join(storageDir, fileName));
                        
                        // Get the file stats to know where to position
                        const filePath = path.join(storageDir, fileName);
                        const stats = await fs.stat(filePath);
                        const fileSize = stats.size;
                        
                        // Open the file for reading and writing
                        const fileHandle = await fs.open(filePath, 'r+');
                        
                        try {
                            // Find the position of the last bracket by reading the end of the file
                            const buffer = Buffer.alloc(Math.min(100, fileSize));
                            await fileHandle.read(buffer, 0, buffer.length, Math.max(0, fileSize - buffer.length));
                            
                            const endPortion = buffer.toString();
                            const lastBracketPos = endPortion.lastIndexOf(']');
                            
                            // Calculate the actual position in the file
                            const actualEndPos = fileSize - buffer.length + lastBracketPos;
                            
                            // Truncate the file to remove the closing bracket
                            await fileHandle.truncate(actualEndPos);
                            
                            // Check if we need a comma (i.e., if the array isn't empty)
                            const checkBuffer = Buffer.alloc(10);
                            await fileHandle.read(checkBuffer, 0, checkBuffer.length, Math.max(0, actualEndPos - 10));
                            const needsComma = checkBuffer.toString().trim().length > 0;
                            
                            // Convert data to string without brackets
                            const dataString = JSON.stringify(data, null, 2)
                                .replace(/^\[/, '')
                                .replace(/\]$/, '');
                            
                            // Write the final content
                            await fileHandle.write(`${needsComma ? ',' : ''}${dataString}]`, actualEndPos);
                            
                            console.log(`Data batch appended to ${filePath}`);
                        } finally {
                            await fileHandle.close();
                        }
                    }
                         catch{
                            // File doesn't exist, create it with the data
                            await fs.writeFile(path.join(storageDir, fileName), JSON.stringify(data, null, 2) + "\n");
                            console.log(`File did not exist. Created ${path.join(storageDir, fileName)} and written data.`);
        
        }
        const endTime = Date.now();
        console.log(`\n${dataType} Files: ${file} insertion completed within ${(endTime - startTime) / 1000} seconds\n----------`);
    }catch (e) {
        console.error("An error occurred: ", e);
    }
    }

    // Define which dataset files will be imported insertion
    async filesToInsertData(dataType: string): Promise<string[]> {
        let targetDir: string;
        let Files: string[] = [];
        if (dataType === 'CWE') {
            targetDir = path.join(this.importPath, "mitre_cwe");
            try {
                const listOfFiles = await fs.readdir(targetDir);
                for (const entry of listOfFiles) {
                    // console.log(entry);
                    if (entry.endsWith('.json')) {
                        // Return a relative path based on importPath
                        Files.push(path.join("mitre_cwe", entry));
                    }
                }
            } catch (e) {
                console.error("Error reading directory: ", e);
            }
        } else if (dataType === 'CPE') {
            targetDir = path.join(this.importPath, "nist", `${dataType}`, "splitted");
            try {
                const listOfFiles = await fs.readdir(targetDir);
                for (const entry of listOfFiles) {
                    // console.log(entry);
                    if (entry.endsWith('.json')) {
                        
                        // Return a relative path based on importPath
                        Files.push(path.join("nist", `${dataType}`, "splitted", entry));
                    }
                }
            } catch (e) {
                console.error("Error reading directory: ", e);
            }}
        else {
            targetDir = path.join(this.importPath, "nist", `${dataType}`);
                try {
                    const listOfFiles = await fs.readdir(targetDir);
                    for (const entry of listOfFiles) {
                        // console.log(entry);
                        if (entry.endsWith('.json')) {
                            
                            // Return a relative path based on importPath
                            Files.push(path.join("nist", `${dataType}`, entry));
                        }
                    }
                } catch (e) {
                    console.error("Error reading directory: ", e);
                }}
        return Files;
    }
};