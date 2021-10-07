import fnmatch
import os
import json
import argparse
import sys
import pefile

importDict = {} # The import dict, 
outLines   = [] # for the final sort

parser = argparse.ArgumentParser(description='importsort - Sort imports from a directory of executable files')
parser.add_argument('-d', dest='directory', help='Directory to parse', required=True)
parser.add_argument('-j', dest='jsonOut', help='Output all data as JSON', action='store_true')
parser.set_defaults(jsonOut=False)
args = parser.parse_args()

def rGlob(treeroot, pattern):
    results = []
    for base, dirs, files in os.walk(treeroot):
        goodfiles = fnmatch.filter(files, pattern)
        results.extend(os.path.join(base, f) for f in goodfiles)
    return results

def getImports(fname):
    try:
        myPE = pefile.PE(fname,fast_load=True)
        myPE.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        myPE.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT']])
        if hasattr(myPE,'DIRECTORY_ENTRY_IMPORT'):
            for entry in myPE.DIRECTORY_ENTRY_IMPORT:
              for imp in entry.imports:
                libName = entry.dll.decode('utf-8')
                if imp.name is not None:
                    fncName = imp.name.decode('utf-8')
                elif imp.ordinal is not None:
                    fncName = "Ordinal_{}".format(imp.ordinal)
                else:
                    fncName = "???"
                if libName not in importDict:
                    importDict[libName] = []
                importDict[libName].append((fncName,infile))
        if hasattr(myPE, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
          for entry in myPE.DIRECTORY_ENTRY_DELAY_IMPORT:
            for imp in entry.imports:
                libName = entry.dll.decode('utf-8')
                if imp.name is not None:
                    fncName = imp.name.decode('utf-8')
                elif imp.ordinal is not None:
                    fncName = "Ordinal_{}".format(imp.ordinal)
                else:
                    fncName = "???"
                if libName not in importDict:
                    importDict[libName] = []
                importDict[libName].append((fncName,infile))
        sys.stderr.write("[+] {}\n".format(infile))
    except pefile.PEFormatError:
        sys.stderr.write("[-] {}\n".format(infile))

if __name__ == '__main__':
    directory = args.directory
    dirlist = rGlob(directory,"*")
    sys.stderr.write("Parsing files in directory...\n")
    for infile in dirlist:
        getImports(infile)
    if args.jsonOut:
        print(json.dumps(importDict))
    else:
        for k in sorted(importDict.keys(), key=lambda x:x.lower()):
            for x in range(0,len(importDict[k])):
                outLines.append("{}\t{}\t{}".format(k,importDict[k][x][0],importDict[k][x][1]))
        print("\nDLL Name\tExported Function\tExecutable")
        print("--------------------------------------------------")
        for l in sorted(outLines):
            print(l)
