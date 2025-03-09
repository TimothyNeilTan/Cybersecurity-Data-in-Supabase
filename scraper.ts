// download.ts
import * as fs from 'fs';
import * as path from 'path';
import AdmZip from 'adm-zip';
import * as cheerio from 'cheerio';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as xml2js from 'xml2js';
import CircuitBreaker from 'opossum';
import { pipeline } from 'stream/promises';
import { createWriteStream } from 'fs';
import { createReadStream } from 'fs';
import { chain } from 'stream-chain';
import { parser } from 'stream-json';
import { pick } from 'stream-json/filters/Pick';
import { streamArray } from 'stream-json/streamers/StreamArray';


const execAsync = promisify(exec);
const MAX_RETRIES = 5;

// Circuit breaker options (customize as needed)
const circuitBreakerOptions = {
  timeout: 10000,
  errorThresholdPercentage: 50,
  resetTimeout: 30000
};

// Wrap the downloadFileToPath function with a circuit breaker
const downloadFileBreaker = new CircuitBreaker(downloadFileToPath, circuitBreakerOptions);

// Helper: make sure a directory exists
function ensureDir(dirPath: string): void {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

// Download and unzip functions for different datasets

export async function downloadFilesCVE(importPath: string): Promise<void> {
  const url = 'https://nvd.nist.gov/vuln/data-feeds';
  const root = 'https://nvd.nist.gov/';
  const res = await fetch(url);
  const html = await res.text();
  const $ = cheerio.load(html);
  const allLinks: string[] = [];
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

export async function downloadFilesCPE(importPath: string): Promise<void> {
    const url = 'https://nvd.nist.gov/vuln/data-feeds';
    const root = 'https://nvd.nist.gov/';
    const res = await fetch(url);
    const html = await res.text();
    const $ = cheerio.load(html);
    const allLinks: string[] = [];
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
        await pipeline(response.body, createWriteStream(filePath));
        await unzipFilesToDirectory(downloadFolder, extractDir, zipFileName);
    }

    await transformXmlFilesToJson(extractDir);
    await transformBigJsonFilesToMultipleJsonFiles(extractDir, 'cpe', 'matches');
    console.log('All CPE datasets downloaded and processed. Exiting.');
    // return;
}

export async function downloadFilesCWE(importPath: string): Promise<void> {
  const url = 'https://cwe.mitre.org/data/archive.html';
  const root = 'https://cwe.mitre.org/';
  const res = await fetch(url);
  const html = await res.text();
  const $ = cheerio.load(html);
  const allLinks: string[] = [];
  const anchors = $('a');
    for (let i = 0; i < anchors.length; i++) {
        const href = $(anchors[i]).attr('href');
        if (href) {
            allLinks.push(href);
        }
    }
  let zipFiles = allLinks.filter(dl => dl.includes('.xml.zip'));
  zipFiles = [zipFiles[0]]
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



export async function downloadDatasets(importPath: string): Promise<void> {
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
async function makeHttpRequestWithRetry(url: string, downloadPath: string, fileName: string, retries = 0): Promise<void> {
  try {
    // Use the circuit breaker to make the HTTP request
    await downloadFileBreaker.fire(url, downloadPath, fileName);
  } catch (error) {
    if (retries < MAX_RETRIES) {
      console.log(`Error occurred: ${error}. Retrying... Attempt ${retries + 1}`);
      await makeHttpRequestWithRetry(url, downloadPath, fileName, retries + 1);
    } else {
      throw new Error(`Max retries reached. Last error: ${error}`);
    }
  }
}

// Download file to specified path
async function downloadFileToPath(url: string, downloadPath: string, fileName: string): Promise<void> {
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
async function unzipFilesToDirectory(zipPath: string, extractPath: string, zipFilename: string): Promise<void> {
  try {
    ensureDir(extractPath);
    const zipFilePath = path.join(zipPath, zipFilename);
    const zip = new AdmZip(zipFilePath);
    zip.extractAllTo(extractPath, true);
    console.log(`${zipFilename} unzipped successfully`);
    console.log('---------');
    fs.unlinkSync(zipFilePath);
  } catch (error) {
    console.error("Error while unzipping data", error);
  }
}

// Convert all XML files in the directory to JSON and then remove the XML files
async function transformXmlFilesToJson(dirPath: string): Promise<void> {
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

async function transformBigJsonFilesToMultipleJsonFiles(dirPath: string, outputPrefix: string, jsonArrayPath: string): Promise<void> {
    const directoryContents = fs.readdirSync(dirPath);
    for (const item of directoryContents) {
        const itemPath = path.join(dirPath, item);
        if (itemPath.endsWith(".json") && fs.statSync(itemPath).isFile()) {
            await processLargeJsonFile(itemPath, dirPath, outputPrefix, 200, jsonArrayPath);
        }
    }
}

async function processLargeJsonFile(inputFile: string, outputPath: string, outputPrefix: string, batchSize: number, jsonArrayPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
        const splittedDir = path.join(outputPath, "splitted");
        ensureDir(splittedDir);
        let batch: any[] = [];
        let fileCount = 0;

        // Build a pipeline that navigates to the nested array using the provided jsonArrayPath.
        // For example, if jsonArrayPath is "CVE_Items", pick will extract that property.
        const pipelineStream = chain([
            createReadStream(inputFile),
            parser(),
            pick({ filter: jsonArrayPath }), // jsonArrayPath should be provided in dot notation (e.g., "CVE_Items")
            streamArray()
        ]);

        pipelineStream.on('data', (data: { key: number; value: any }) => {
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

        pipelineStream.on('error', (err: Error) => {
            reject(err);
        });
    });
}

// Convert a single XML file to JSON
async function xmlFileToJson(xmlFilePath: string): Promise<void> {
  console.log(`Transforming file ${xmlFilePath}`);
  const xmlContent = fs.readFileSync(xmlFilePath, { encoding: 'utf-8' });
  const parser = new xml2js.Parser();
  const dataObj = await parser.parseStringPromise(xmlContent);
  const jsonData = JSON.stringify(dataObj, null, 4);
  const jsonFile = xmlFilePath.replace(".xml", ".json");
  fs.writeFileSync(jsonFile, jsonData);
}

// Replace unwanted string in CWE JSON file
async function replaceUnwantedStringCWE(dirPath: string): Promise<void> {
  const files = fs.readdirSync(dirPath).filter(entry => entry.endsWith(".json") && entry.startsWith("cwec"));
  if (files.length === 0) return;
  const filePath = path.join(dirPath, files[0]);
  const data = fs.readFileSync(filePath, 'utf-8');
  const replacedData = data.replace(/"@/g, '"');
  const flattenedFile = path.join(dirPath, "cwe.json");
  fs.writeFileSync(flattenedFile, replacedData);
  // fs.unlinkSync(filePath);
}
// Run the downloadDatasets function
downloadDatasets(path.join(__dirname, '..' ,'storageDir'));