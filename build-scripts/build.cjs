'use strict'

const shell = require('shelljs')
const chalk = require('chalk')
const fs = require('fs')

const NPM_DIR = `dist`

shell.echo(`Copying package files...`)
shell.cp(`-Rf`, [`package.json`, `LICENSE`, `*.md`], `${NPM_DIR}`)

shell.echo(`Modifying final package.json`)
const raw = fs.readFileSync(`./${NPM_DIR}/package.json`, 'utf8')
// dist/ becomes the package root when published, remove "dist/" from all entrypoint paths
const packageJSON = JSON.parse(raw.replace(/(\.\/)?dist\//g, (m, dot) => dot || ''))
packageJSON.private = false
delete packageJSON.scripts
delete packageJSON.devDependencies
delete packageJSON.resolutions

fs.writeFileSync(`./${NPM_DIR}/package.json`, JSON.stringify(packageJSON, null, 2))

shell.echo(chalk.green(`End building`))
