import * as dLEverything from './scraper';
import dataInserter from './mainNodeDataInsert';
import * as path from 'path';

dLEverything.downloadDatasets(path.join(process.cwd(), '/storageDir'));
const inserter = new dataInserter();
inserter.dataInsertion();


