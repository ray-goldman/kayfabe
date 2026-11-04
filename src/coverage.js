'use strict';
const path = require('node:path');
const { detectLanguage } = require('./languages');
const { isTestPath } = require('./util');
const { CARGO_SNAPSHOT } = require('./supply');
const SUPPORTED = new Set(['javascript','typescript','python','php','java','kotlin','go','ruby','csharp','shell']);
const UNSUPPORTED = {'.rs':'rust','.c':'c','.h':'c','.cc':'cpp','.cpp':'cpp','.cxx':'cpp','.hpp':'cpp','.hh':'cpp','.swift':'swift','.dart':'dart','.lua':'lua','.pl':'perl','.ex':'elixir','.exs':'elixir','.m':'objective-c','.mm':'objective-cpp'};
function sourceLanguage(file) {
  const logical=file.replace(/\.appsec-quarantined$/,'');
  return UNSUPPORTED[path.extname(logical).toLowerCase()] || (SUPPORTED.has(detectLanguage(logical)) ? detectLanguage(logical) : null);
}
function buildCoverage({files,fileData,skipped,truncated,limits,supply,opts,readFailures=0,osvStatus='not-requested'}) {
  const languages = Object.create(null); let excludedTests=0, excludedVendored=0;
  const rust={status:'partial',eligibleFiles:0,lexedFiles:0,discoveredFunctions:0,analyzedFunctions:0,resolvedBuilderChains:0,moduleScopes:0,reachableFiles:0,conditionalFiles:0,excludedFiles:0,unreachableFiles:0,cfgExcludedItems:0,cfgUnknownItems:0,cfgUnknownConditions:0,diagnosticCounts:Object.create(null),note:'Bounded module graph, three-state cfg, plain functions and resolved reqwest chains. Target/feature cfg stays unresolved; scanner host settings are not Rust build settings. No macro expansion, custom module paths, trait/type inference, variable builder flow or cross-file taint. Counts do not measure vulnerability recall.'};
  for(const f of files) {
    const lang=sourceLanguage(f.rel);if(!lang)continue;
    if(fileData.get(f.rel)?.vendored){excludedVendored++;continue;}
    if(!opts.includeTests&&isTestPath(f.rel.replace(/\.appsec-quarantined$/,''))){excludedTests++;continue;}
    const row=languages[lang] ||= {files:0,analyzedFiles:0,unsupportedFiles:0};row.files++;
    if(SUPPORTED.has(lang)&&fileData.get(f.rel)?.sourceAnalyzed)row.analyzedFiles++;
    else if(!SUPPORTED.has(lang))row.unsupportedFiles++;
    if(lang==='rust') {
      rust.eligibleFiles++;const r=fileData.get(f.rel)?.rustCoverage;
      if(r){row.partiallyAnalyzedFiles=(row.partiallyAnalyzedFiles||0)+1;rust.lexedFiles+=Number(r.lexed);rust.discoveredFunctions+=r.discoveredFunctions;rust.analyzedFunctions+=r.analyzedFunctions;rust.resolvedBuilderChains+=r.resolvedBuilderChains;
        rust.moduleScopes+=r.moduleScopes||0;rust.cfgExcludedItems+=r.cfgExcludedItems||0;rust.cfgUnknownItems+=r.cfgUnknownItems||0;
        rust.cfgUnknownConditions+=r.cfgUnknownConditions||0;
        if(r.moduleStatus)rust[r.moduleStatus+'Files']++;
        for(const d of r.diagnostics)rust.diagnosticCounts[d.code]=(rust.diagnosticCounts[d.code]||0)+1;}
      else rust.diagnosticCounts['rust-omitted-file']=(rust.diagnosticCounts['rust-omitted-file']||0)+1;
    }
  }
  const sourceFiles=Object.values(languages).reduce((n,r)=>n+r.files,0),analyzedFiles=Object.values(languages).reduce((n,r)=>n+r.analyzedFiles,0),unsupportedFiles=Object.values(languages).reduce((n,r)=>n+r.unsupportedFiles,0);
  const interrupted=!!(truncated||limits.depth||limits.unreadable||limits.large||readFailures||skipped.symlinks.length||opts.repoSymlinks?.length);
  const cargo=supply.cargo,diagnostics=cargo.inputs.flatMap(i=>i.diagnostics.map(d=>({file:i.file,...d})));
  return {
    schema:'kayfabe/coverage@1',
    source:{status:interrupted||unsupportedFiles||analyzedFiles<sourceFiles?'incomplete':sourceFiles?'complete':'not-applicable',files:sourceFiles,analyzedFiles,unsupportedFiles,languages,...(rust.eligibleFiles?{rust:{...rust,fileRatio:rust.lexedFiles/rust.eligibleFiles,functionRatio:rust.discoveredFunctions?rust.analyzedFunctions/rust.discoveredFunctions:null}}:{}),note:'Complete means available source checks ran on selected known source files, not exhaustive detection or full parsing. Rust has partial source checks and remains unsupported for a complete-coverage gate. Other extensions may also be unsupported.'},
    inventory:{status:'limited',note:'Legacy ecosystem inventory parsers have no completeness guarantee. Cargo completeness describes metadata parsing, not dependency resolution, installation or reachability.',cargo:{status:diagnostics.length||interrupted?'incomplete':cargo.inputs.length?'complete':'not-applicable',inputs:cargo.inputs,resolvedPackages:cargo.inventory.filter(d=>d.resolution==='locked').length,requirements:cargo.inventory.filter(d=>d.resolution==='requirement').length,publicRegistryPackages:cargo.inventory.filter(d=>d.publicRegistry).length,diagnostics}},
    advisories:{status:'limited',note:'Curated advisory coverage is limited; absence of matches is not a clean bill of health.',cargoSnapshot:{date:CARGO_SNAPSHOT.date,commit:CARGO_SNAPSHOT.commit,advisories:CARGO_SNAPSHOT.advisories.length,scope:CARGO_SNAPSHOT.scope},online:{status:osvStatus}},
    scope:{includeTests:!!opts.includeTests,excludedTests,excludedVendored,excludedEntries:skipped.excluded||0,skippedDirectories:skipped.dirs,symlinks:skipped.symlinks.length+(opts.repoSymlinks?.length||0),limits:{...limits,readFailures,truncated},note:'Default build/vendor directories, explicit excludes and excluded tests are outside the selected scope. Directory contents are not inventoried.'},
  };
}
function coverageGate(result,required=false) {
  const c=result.coverage,known=c?.schema==='kayfabe/coverage@1';
  const complete=known&&c.source.status==='complete'&&c.source.files>0&&c.inventory.cargo.status!=='incomplete';
  return {required:!!required,passed:!required||!!complete,status:known?(complete?'complete':'incomplete'):'unknown',reason:!known?'Coverage unknown: rescan with a coverage-aware version.':complete?'Available source checks completed in the selected scope; advisory breadth remains limited.':'Incomplete coverage: unsupported/omitted source, no selected source, or incomplete Cargo inventory. Severity findings are evaluated separately.'};
}
function coverageText(result) {
  const c=result.coverage;if(!c)return 'Coverage unknown: this report predates coverage reporting; rescan to measure it.';
  const cargo=c.inventory.cargo;
  const rust=c.source.rust?` Rust partial: ${c.source.rust.lexedFiles}/${c.source.rust.eligibleFiles} files tokenized, ${c.source.rust.analyzedFunctions}/${c.source.rust.discoveredFunctions} functions in the supported subset, ${c.source.rust.resolvedBuilderChains} resolved builder chains.${c.source.rust.moduleScopes!=null?` Module contexts ${c.source.rust.moduleScopes}; cfg excluded ${c.source.rust.cfgExcludedItems}, unresolved ${c.source.rust.cfgUnknownItems}.`:''}`:'';
  return `${coverageGate(result,true).passed?'Source coverage: available checks completed':'Incomplete coverage'} — source ${c.source.analyzedFiles}/${c.source.files} selected files; unsupported ${c.source.unsupportedFiles}.${rust} Cargo inventory: ${cargo.status}, ${cargo.resolvedPackages} locked packages, ${cargo.requirements} requirements. Advisory coverage: limited; Cargo snapshot ${c.advisories.cargoSnapshot.date} (${c.advisories.cargoSnapshot.advisories} advisory); OSV ${c.advisories.online.status}.`;
}
module.exports={buildCoverage,coverageGate,coverageText,sourceLanguage};
