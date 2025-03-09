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
exports.downloadFilesCVE = downloadFilesCVE;
exports.downloadFilesCPE = downloadFilesCPE;
exports.downloadFilesCWE = downloadFilesCWE;
exports.downloadDatasets = downloadDatasets;
// download.ts
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const adm_zip_1 = __importDefault(require("adm-zip"));
const cheerio = __importStar(require("cheerio"));
const child_process_1 = require("child_process");
const util_1 = require("util");
const xml2js = __importStar(require("xml2js"));
const opossum_1 = __importDefault(require("opossum"));
const promises_1 = require("stream/promises");
const fs_1 = require("fs");
const fs_2 = require("fs");
const stream_chain_1 = require("stream-chain");
const stream_json_1 = require("stream-json");
const Pick_1 = require("stream-json/filters/Pick");
const StreamArray_1 = require("stream-json/streamers/StreamArray");
const execAsync = (0, util_1.promisify)(child_process_1.exec);
const MAX_RETRIES = 5;
// Circuit breaker options (customize as needed)
const circuitBreakerOptions = {
    timeout: 10000,
    errorThresholdPercentage: 50,
    resetTimeout: 30000
};
// Wrap the downloadFileToPath function with a circuit breaker
const downloadFileBreaker = new opossum_1.default(downloadFileToPath, circuitBreakerOptions);
// Helper: make sure a directory exists
function ensureDir(dirPath) {
    if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
    }
}
// Download and unzip functions for different datasets
async function downloadFilesCVE(importPath) {
    const url = 'https://nvd.nist.gov/vuln/data-feeds';
    const root = 'https://nvd.nist.gov/';
    const res = await fetch(url);
    const html = await res.text();
    const $ = cheerio.load(html);
    const allLinks = [];
    $('a').each((_, el) => {
        const href = $(el).attr('href');
        if (href) {
            allLinks.push(href);
        }
    });
    const zipFiles = allLinks.filter(dl => dl.includes('.json.zip') && dl.includes('nvdcve'));
    const downloadFolder = path.join(importPath, "nist", "cve") + path.sep;
    const extractDir = downloadFolder;
    console.log('\nUpdating the Database with the latest CVE Files...');
    for (const zipFile of zipFiles) {
        console.log("Zip file: ", zipFile);
        const fullUrl = root + zipFile;
        const zipFileName = path.basename(zipFile);
        await makeHttpRequestWithRetry(fullUrl, downloadFolder, zipFileName);
        await unzipFilesToDirectory(downloadFolder, extractDir, zipFileName);
    }
    console.log('All CVE datasets downloaded and processed. Exiting.');
}
async function downloadFilesCPE(importPath) {
    const url = 'https://nvd.nist.gov/vuln/data-feeds';
    const root = 'https://nvd.nist.gov/';
    const res = await fetch(url);
    const html = await res.text();
    const $ = cheerio.load(html);
    const allLinks = [];
    $('a').each((_, el) => {
        const href = $(el).attr('href');
        if (href) {
            allLinks.push(href);
        }
    });
    const zipFiles = allLinks.filter(dl => dl.includes('.json.zip') && dl.includes('nvdcpematch'));
    const downloadFolder = path.join(importPath, "nist", "cpe") + path.sep;
    const extractDir = downloadFolder;
    // Ensure download folder exists before streaming files into it.
    ensureDir(downloadFolder);
    console.log('\nUpdating the Database with the latest CPE Files...');
    for (const zipFile of zipFiles) {
        const fullUrl = root + zipFile;
        const zipFileName = path.basename(zipFile);
        const filePath = path.join(downloadFolder, zipFileName);
        console.log("Downloading: ", fullUrl);
        const response = await fetch(fullUrl);
        if (!response.ok || !response.body) {
            throw new Error(`Failed to download file: ${response.statusText}`);
        }
        // Stream the response body directly into a file
        await (0, promises_1.pipeline)(response.body, (0, fs_1.createWriteStream)(filePath));
        await unzipFilesToDirectory(downloadFolder, extractDir, zipFileName);
    }
    await transformXmlFilesToJson(extractDir);
    await transformBigJsonFilesToMultipleJsonFiles(extractDir, 'cpe', 'matches');
    console.log('All CPE datasets downloaded and processed. Exiting.');
    // return;
}
async function downloadFilesCWE(importPath) {
    const url = 'https://cwe.mitre.org/data/archive.html';
    const root = 'https://cwe.mitre.org/';
    const res = await fetch(url);
    const html = await res.text();
    const $ = cheerio.load(html);
    const allLinks = [];
    const anchors = $('a');
    for (let i = 0; i < anchors.length; i++) {
        const href = $(anchors[i]).attr('href');
        if (href) {
            allLinks.push(href);
        }
    }
    let zipFiles = allLinks.filter(dl => dl.includes('.xml.zip'));
    zipFiles = [zipFiles[0]];
    const downloadFolder = path.join(importPath, "mitre_cwe") + path.sep;
    const extractDir = downloadFolder;
    for (const zipFile of zipFiles) {
        const fullUrl = root + zipFile;
        const zipFileName = path.basename(zipFile);
        await makeHttpRequestWithRetry(fullUrl, downloadFolder, zipFileName);
        await unzipFilesToDirectory(downloadFolder, extractDir, zipFileName);
        await transformXmlFilesToJson(extractDir);
        await replaceUnwantedStringCWE(extractDir);
        await transformBigJsonFilesToMultipleJsonFiles(extractDir, 'cwe_view', 'Weakness_Catalog.Views.View');
        await makeHttpRequestWithRetry(fullUrl, downloadFolder, zipFileName);
        await unzipFilesToDirectory(downloadFolder, extractDir, zipFileName);
    }
    console.log('All CWE datasets downloaded and processed. Exiting.');
}
async function downloadDatasets(importPath) {
    try {
        await downloadFilesCVE(importPath);
        await downloadFilesCPE(importPath);
        await downloadFilesCWE(importPath);
    }
    catch (error) {
        console.error("Error downloading datasets: ", error);
    }
}
// HTTP request with retry logic
async function makeHttpRequestWithRetry(url, downloadPath, fileName, retries = 0) {
    try {
        // Use the circuit breaker to make the HTTP request
        await downloadFileBreaker.fire(url, downloadPath, fileName);
    }
    catch (error) {
        if (retries < MAX_RETRIES) {
            console.log(`Error occurred: ${error}. Retrying... Attempt ${retries + 1}`);
            await makeHttpRequestWithRetry(url, downloadPath, fileName, retries + 1);
        }
        else {
            throw new Error(`Max retries reached. Last error: ${error}`);
        }
    }
}
// Download file to specified path
async function downloadFileToPath(url, downloadPath, fileName) {
    console.log("Download path: ", downloadPath);
    ensureDir(downloadPath);
    const res = await fetch(url);
    if (!res.ok) {
        throw new Error(`Failed to download file: ${res.statusText}`);
    }
    const arrayBuffer = await res.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    const dlPath = path.join(downloadPath, fileName);
    fs.writeFileSync(dlPath, buffer);
}
// Unzip file and remove zip afterwards
async function unzipFilesToDirectory(zipPath, extractPath, zipFilename) {
    try {
        ensureDir(extractPath);
        const zipFilePath = path.join(zipPath, zipFilename);
        const zip = new adm_zip_1.default(zipFilePath);
        zip.extractAllTo(extractPath, true);
        console.log(`${zipFilename} unzipped successfully`);
        console.log('---------');
        fs.unlinkSync(zipFilePath);
    }
    catch (error) {
        console.error("Error while unzipping data", error);
    }
}
// Convert all XML files in the directory to JSON and then remove the XML files
async function transformXmlFilesToJson(dirPath) {
    const directoryContents = fs.readdirSync(dirPath);
    for (const item of directoryContents) {
        const itemPath = path.join(dirPath, item);
        if (itemPath.endsWith(".xml") && fs.statSync(itemPath).isFile()) {
            await xmlFileToJson(itemPath);
            fs.unlinkSync(itemPath);
        }
    }
}
// For large JSON files, slice them into smaller JSON files
// Streaming implementation to split large JSON files into multiple files by processing a nested array.
async function transformBigJsonFilesToMultipleJsonFiles(dirPath, outputPrefix, jsonArrayPath) {
    const directoryContents = fs.readdirSync(dirPath);
    for (const item of directoryContents) {
        const itemPath = path.join(dirPath, item);
        if (itemPath.endsWith(".json") && fs.statSync(itemPath).isFile()) {
            await processLargeJsonFile(itemPath, dirPath, outputPrefix, 200, jsonArrayPath);
        }
    }
}
async function processLargeJsonFile(inputFile, outputPath, outputPrefix, batchSize, jsonArrayPath) {
    return new Promise((resolve, reject) => {
        const splittedDir = path.join(outputPath, "splitted");
        ensureDir(splittedDir);
        let batch = [];
        let fileCount = 0;
        // Build a pipeline that navigates to the nested array using the provided jsonArrayPath.
        // For example, if jsonArrayPath is "CVE_Items", pick will extract that property.
        const pipelineStream = (0, stream_chain_1.chain)([
            (0, fs_2.createReadStream)(inputFile),
            (0, stream_json_1.parser)(),
            (0, Pick_1.pick)({ filter: jsonArrayPath }), // jsonArrayPath should be provided in dot notation (e.g., "CVE_Items")
            (0, StreamArray_1.streamArray)()
        ]);
        pipelineStream.on('data', (data) => {
            batch.push(data.value);
            if (batch.length === batchSize) {
                fileCount++;
                const outputFile = path.join(splittedDir, `${outputPrefix}_output_file_${fileCount}.json`);
                fs.writeFileSync(outputFile, JSON.stringify(batch, null, 4));
                batch = [];
            }
        });
        pipelineStream.on('end', () => {
            if (batch.length > 0) {
                fileCount++;
                const outputFile = path.join(splittedDir, `${outputPrefix}_output_file_${fileCount}.json`);
                fs.writeFileSync(outputFile, JSON.stringify(batch, null, 4));
            }
            resolve();
        });
        pipelineStream.on('error', (err) => {
            reject(err);
        });
    });
}
// Convert a single XML file to JSON
async function xmlFileToJson(xmlFilePath) {
    console.log(`Transforming file ${xmlFilePath}`);
    const xmlContent = fs.readFileSync(xmlFilePath, { encoding: 'utf-8' });
    const parser = new xml2js.Parser();
    const dataObj = await parser.parseStringPromise(xmlContent);
    const jsonData = JSON.stringify(dataObj, null, 4);
    const jsonFile = xmlFilePath.replace(".xml", ".json");
    fs.writeFileSync(jsonFile, jsonData);
}
// Replace unwanted string in CWE JSON file
async function replaceUnwantedStringCWE(dirPath) {
    const files = fs.readdirSync(dirPath).filter(entry => entry.endsWith(".json") && entry.startsWith("cwec"));
    if (files.length === 0)
        return;
    const filePath = path.join(dirPath, files[0]);
    const data = fs.readFileSync(filePath, 'utf-8');
    const replacedData = data.replace(/"@/g, '"');
    const flattenedFile = path.join(dirPath, "cwe.json");
    fs.writeFileSync(flattenedFile, replacedData);
    // fs.unlinkSync(filePath);
}
// Run the downloadDatasets function
// downloadDatasets(path.join(__dirname, '..' ,'storageDir'));
