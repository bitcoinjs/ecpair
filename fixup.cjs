const fs = require('fs');
const path = require('path');

const updateRequires = (filePath) => {
  let content = fs.readFileSync(filePath, 'utf8');
  //replace local imports eg. require('./ecpair') to require('ecpair.cjs')
  content = content.replace(/require\('\.\/([^']*)'\)/g, "require('./$1.cjs')");

  fs.writeFileSync(filePath, content, 'utf8');
};

const updateImports = (filePath) => {
  let content = fs.readFileSync(filePath, 'utf8');
  //replace local imports eg. from './types'; to from './types.js';
  content = content.replace(/from '\.\/([^']*)'/g, "from './$1.js'");

  fs.writeFileSync(filePath, content, 'utf8');
};

const processFiles = (dir) => {
  fs.readdirSync(dir).forEach((file) => {
    const filePath = path.join(dir, file);
    if (fs.lstatSync(filePath).isDirectory()) {
      processFiles(filePath);
    } else if (filePath.endsWith('.cjs')) {
      updateRequires(filePath);
    } else if (filePath.endsWith('.js')) {
      updateImports(filePath);
    }
  });
};

const dir = path.join(__dirname, 'src');
processFiles(dir);
