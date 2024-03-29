
const fs = require('fs');
const path = require('path');
const globby = require('globby');

const bannerSourcePath = path.join(__dirname, 'license-template.txt')
const files = globby.sync(path.join(__dirname, '..', '{*.{js,ts},test/spec/*.js}'))

const bannerSource = fs.readFileSync(bannerSourcePath).toString()
const copyrightRegex = /(Copyright \(c\) )([0-9]+)-Present/

files.forEach(file => {
  const contents = fs.readFileSync(file).toString()
  const match = contents.match(copyrightRegex)
  if (!match) {
    return fs.writeFileSync(file, bannerSource + '\n\n' + contents)
  }
})