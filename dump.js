import fs from 'fs';
import path from 'path';

const OUTPUT_FILE = 'project_dump.txt';
const IGNORED_DIRS = new Set(['node_modules', '.git', '.vscode', 'dist', 'build']);
const ALLOWED_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.json']);

function generateTree(dir, prefix = '') {
  let treeStr = '';
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  const filteredEntries = entries.filter(
    (e) => !IGNORED_DIRS.has(e.name) && e.name !== OUTPUT_FILE && !e.name.startsWith('.')
  );

  filteredEntries.forEach((entry, index) => {
    const isLast = index === filteredEntries.length - 1;
    const pointer = isLast ? '└── ' : '├── ';
    treeStr += `${prefix}${pointer}${entry.name}\n`;

    if (entry.isDirectory()) {
      const nextPrefix = prefix + (isLast ? '    ' : '│   ');
      treeStr += generateTree(path.join(dir, entry.name), nextPrefix);
    }
  });

  return treeStr;
}

function collectFiles(dir) {
  let fileList = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry.name) || entry.name.startsWith('.') || entry.name === OUTPUT_FILE) {
      continue;
    }

    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      fileList = fileList.concat(collectFiles(fullPath));
    } else if (ALLOWED_EXTENSIONS.has(path.extname(entry.name))) {
      fileList.push(fullPath);
    }
  }

  return fileList;
}

function main() {
  const rootDir = process.cwd();
  let outputContent = '';

  // 1. Dizin Ağacı
  outputContent += '==================================================\n';
  outputContent += 'PROJECT FILE TREE\n';
  outputContent += '==================================================\n\n';
  outputContent += path.basename(rootDir) + '/\n';
  outputContent += generateTree(rootDir);
  outputContent += '\n\n';

  // 2. Dosya İçerikleri
  outputContent += '==================================================\n';
  outputContent += 'FILE CONTENTS\n';
  outputContent += '==================================================\n\n';

  const files = collectFiles(rootDir);

  for (const file of files) {
    const relativePath = path.relative(rootDir, file);
    const content = fs.readFileSync(file, 'utf-8');

    outputContent += `--- START OF FILE: ${relativePath} ---\n`;
    outputContent += content;
    outputContent += `\n--- END OF FILE: ${relativePath} ---\n\n`;
  }

  fs.writeFileSync(path.join(rootDir, OUTPUT_FILE), outputContent, 'utf-8');
  console.log(`Tamamlandı! Tüm içerik ${OUTPUT_FILE} dosyasına kaydedildi.`);
}

main();