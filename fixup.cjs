const fs = require('fs');
const path = require('path');

const updateRequireStatements = (filePath) => {
  let content = fs.readFileSync(filePath, 'utf8');

  // Replace require('./something.js') with require('./something.cjs')
  content = content.replace(/require\('\.\/([^']*)\.js'\)/g, "require('./$1.cjs')");

  // Replace import/export in .d.ts files
  content = content.replace(/from '\.\/([^']*)\.js'/g, "from './$1.cjs'");

  fs.writeFileSync(filePath, content, 'utf8');
};

const processFiles = (dir) => {
  fs.readdirSync(dir).forEach((file) => {
    const filePath = path.join(dir, file);
    const newPath = filePath.replace('.js', '.cjs');

    if (fs.lstatSync(filePath).isDirectory()) {
      processFiles(filePath);
    } else if (path.extname(file) === '.js') {
      // Rename the .js file to .cjs
      updateRequireStatements(filePath);

      fs.renameSync(filePath, newPath);
    }

    // Update .d.ts files to replace .js references with .cjs
    if (path.extname(file) === '.ts') {
      updateRequireStatements(filePath);
    }
  });
};

const dir = path.join(__dirname, 'src', 'cjs');
processFiles(dir);
