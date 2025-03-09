"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs_1 = require("fs");
const path = __importStar(require("path"));
const supabase_config_1 = __importDefault(require("./supabase_config"));
const cpeDataExtract_1 = __importDefault(require("./cpeDataExtract"));
const cveDataExtract_1 = __importDefault(require("./cveDataExtract"));
const cweDataExtract_1 = __importDefault(require("./cweDataExtract"));
class dataInserter {
    constructor(supabase = supabase_config_1.default) {
        this.supabase = supabase_config_1.default;
        this.supabase = supabase;
        this.importPath = path.join(__dirname, '..', 'storageDir');
    }
    async dataInsertion() {
        const differentDataTypes = 
        // if you want to generate the CVE <-> CPE relationships you can uncomment the lines 68-78
        // (granted though that it will generate 13million + new records so do it at your own risk)
        // You will need to go to the cveDataExtract and uncomment the lines in 88-106 as well
        ['CWE', 'CPE', 'CVE', 'cverelationships'];
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
            }
            ;
            // const files = await this.filesToInsertData(dataType);
            // console.log(`Files to insert: ${files}`); 
            for (const file of files) {
                console.log(file);
                console.log(dataType);
                const fullFilePath = path.join(this.importPath, file);
                let fileContent = await fs_1.promises.readFile(fullFilePath, 'utf8');
                fileContent = JSON.parse(fileContent);
                // Assuming file content is newline-delimited JSON objects
                //--------CPE--------//
                if (dataType === 'CPE') {
                    {
                        const cpeData = new cpeDataExtract_1.default();
                        const cpeNodes = cpeData.cpeDataExtract(fileContent);
                        try {
                            for (let i = 0; i < cpeNodes.length; i += BATCH_SIZE) {
                                const batch = cpeNodes.slice(i, i + BATCH_SIZE);
                                await this.queryDataScript(batch, 'CPE');
                                console.log(`Inserted batch ${Math.floor(i / BATCH_SIZE) + 1}`);
                            }
                            console.log('Inserted CPE data');
                        }
                        catch (e) {
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
                    }
                }
                //--------CWE--------//
                else if (dataType === 'CWE') {
                    const cweData = new cweDataExtract_1.default();
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
                    const cveData = new cveDataExtract_1.default();
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
                    const cveData = new cveDataExtract_1.default();
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
                    const cpeData = new cpeDataExtract_1.default();
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
            }
        }
    }
    // SQL Query to insert data
    async queryDataScript(file, dataType) {
        const startTime = Date.now();
        try {
            const { data, error } = await this.supabase
                .from(`${dataType}`)
                .upsert(file)
                .select();
            console.log(error);
            const storageDir = path.join(__dirname, "..", 'dataStorage');
            const fileName = `${dataType}_batch.json`;
            try {
                await fs_1.promises.access(path.join(storageDir, fileName));
                // Get the file stats to know where to position
                const filePath = path.join(storageDir, fileName);
                const stats = await fs_1.promises.stat(filePath);
                const fileSize = stats.size;
                // Open the file for reading and writing
                const fileHandle = await fs_1.promises.open(filePath, 'r+');
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
                }
                finally {
                    await fileHandle.close();
                }
            }
            catch {
                // File doesn't exist, create it with the data
                await fs_1.promises.writeFile(path.join(storageDir, fileName), JSON.stringify(data, null, 2) + "\n");
                console.log(`File did not exist. Created ${path.join(storageDir, fileName)} and written data.`);
            }
            const endTime = Date.now();
            console.log(`\n${dataType} Files: ${file} insertion completed within ${(endTime - startTime) / 1000} seconds\n----------`);
        }
        catch (e) {
            console.error("An error occurred: ", e);
        }
    }
    // Define which dataset files will be imported insertion
    async filesToInsertData(dataType) {
        let targetDir;
        let Files = [];
        if (dataType === 'CWE') {
            targetDir = path.join(this.importPath, "mitre_cwe");
            try {
                const listOfFiles = await fs_1.promises.readdir(targetDir);
                for (const entry of listOfFiles) {
                    // console.log(entry);
                    if (entry.endsWith('.json')) {
                        // Return a relative path based on importPath
                        Files.push(path.join("mitre_cwe", entry));
                    }
                }
            }
            catch (e) {
                console.error("Error reading directory: ", e);
            }
        }
        else if (dataType === 'CPE') {
            targetDir = path.join(this.importPath, "nist", `${dataType}`, "splitted");
            try {
                const listOfFiles = await fs_1.promises.readdir(targetDir);
                for (const entry of listOfFiles) {
                    // console.log(entry);
                    if (entry.endsWith('.json')) {
                        // Return a relative path based on importPath
                        Files.push(path.join("nist", `${dataType}`, "splitted", entry));
                    }
                }
            }
            catch (e) {
                console.error("Error reading directory: ", e);
            }
        }
        else {
            targetDir = path.join(this.importPath, "nist", `${dataType}`);
            try {
                const listOfFiles = await fs_1.promises.readdir(targetDir);
                for (const entry of listOfFiles) {
                    // console.log(entry);
                    if (entry.endsWith('.json')) {
                        // Return a relative path based on importPath
                        Files.push(path.join("nist", `${dataType}`, entry));
                    }
                }
            }
            catch (e) {
                console.error("Error reading directory: ", e);
            }
        }
        return Files;
    }
}
exports.default = dataInserter;
;
