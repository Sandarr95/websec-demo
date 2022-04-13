const fs = require('fs/promises');
const dbFile = process.env.DB_FILE || './db.json';
let db = require(dbFile);
let writeQueue = Promise.resolve();

function get() {
  return JSON.parse(JSON.stringify(db));
}

function update(fn) {
  const dbFreeze = get();
  const newDb = fn(dbFreeze);
  enqueue(newDb);
  db = newDb;
  return get();
}

function enqueue(newState) {
  writeQueue = writeQueue.then(() => fs.writeFile(dbFile, JSON.stringify(newState, null, 2)).catch(e => console.error(e)));
}

module.exports = {
  get, update
}
