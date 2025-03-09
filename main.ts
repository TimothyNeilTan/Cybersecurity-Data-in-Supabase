import * as dLEverything from './scraper';
import dataInserter from './mainNodeDataInsert';
import * as path from 'path';

const inserter = new dataInserter();

// console.log(path.join(__dirname, '..'))
// dLEverything.downloadDatasets(path.join(__dirname, '..' ,'storageDir'));
// inserter.dataInsertion();

async function runAll() {
    try {
      await dLEverything.downloadDatasets(path.join(__dirname, '..', 'storageDir'));
      await inserter.dataInsertion();
    } catch (err) {
      console.error(err);
    }
  }
runAll();
  