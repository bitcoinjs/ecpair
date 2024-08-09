const fs = require('fs');
const path = require('path');

// Function to update require statements in a file
const updateRequires = (filePath) => {
  // Read the content of the file
  let content = fs.readFileSync(filePath, 'utf8');

  // Define the regex pattern to match local require statements
  // const regex = /require\((['"])(\.\/[^'"]*)\1\)/g;

  // Replace the matched patterns with the updated path
  content = content.replace(/require\('\.\/([^']*)'\)/g, "require('./$1.cjs')");

  // Write the updated content back to the file
  fs.writeFileSync(filePath, content, 'utf8');
};

// Function to process all .cjs files in the src/cjs directory
const processFiles = (dir) => {
  fs.readdirSync(dir).forEach((file) => {
    const filePath = path.join(dir, file);
    if (fs.lstatSync(filePath).isDirectory()) {
      processFiles(filePath); // Recursively process subdirectories
    } else if (filePath.endsWith('.cjs')) {
      updateRequires(filePath);
    }
  });
};

// Directory to process
const dir = path.join(__dirname, 'src', 'cjs');
processFiles(dir);
