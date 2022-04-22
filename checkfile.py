import pefile
import os
import array
import math
import pickle
import joblib
import sys
import argparse

def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0]*256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x*math.log(p_x, 2)

    return entropy

def get_resources(pe):
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources

def get_ver_info(pe):
    resource = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    resource[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                resource[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
          resource['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
          resource['os'] = pe.VS_FIXEDFILEINFO.FileOS
          resource['type'] = pe.VS_FIXEDFILEINFO.FileType
          resource['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
          resource['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
          resource['signature'] = pe.VS_FIXEDFILEINFO.Signature
          resource['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return resource

def extract_infos(fpath):
    resource = {}
    pe = pefile.PE(fpath)
    resource['Machine'] = pe.FILE_HEADER.Machine
    resource['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    resource['Characteristics'] = pe.FILE_HEADER.Characteristics
    resource['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    resource['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    resource['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    resource['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    resource['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    resource['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    resource['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    try:
        resource['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        resource['BaseOfData'] = 0
    resource['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    resource['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    resource['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    resource['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    resource['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    resource['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    resource['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    resource['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    resource['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    resource['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    resource['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    resource['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    resource['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    resource['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    resource['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    resource['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    resource['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    resource['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    resource['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    resource['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    resource['SectionsNb'] = len(pe.sections)
    entropy = list(map(lambda x:x.get_entropy(), pe.sections))
    resource['SectionsMeanEntropy'] = sum(entropy)/float(len(entropy))
    resource['SectionsMinEntropy'] = min(entropy)
    resource['SectionsMaxEntropy'] = max(entropy)

    raw_sizes = list(map(lambda x:x.SizeOfRawData, pe.sections))
    resource['SectionsMeanRawsize'] = sum(raw_sizes)/float(len(raw_sizes))
    resource['SectionsMinRawsize'] = min(raw_sizes)
    resource['SectionsMaxRawsize'] = max(raw_sizes)
    virtual_sizes = list(map(lambda x:x.Misc_VirtualSize, pe.sections))
    resource['SectionsMeanVirtualsize'] = sum(virtual_sizes)/float(len(virtual_sizes))
    resource['SectionsMinVirtualsize'] = min(virtual_sizes)
    resource['SectionMaxVirtualsize'] = max(virtual_sizes)

    try:
        resource['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = list(sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], []))
        resource['ImportsNb'] = len(imports)
        resource['ImportsNbOrdinal'] = len(list(filter(lambda x:x.name is None, imports)))
    except AttributeError:
        resource['ImportsNbDLL'] = 0
        resource['ImportsNb'] = 0
        resource['ImportsNbOrdinal'] = 0

    try:
        resource['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        resource['ExportNb'] = 0
    resources= get_resources(pe)
    resource['ResourcesNb'] = len(resources)
    if len(resources)> 0:
        entropy = list(map(lambda x:x[0], resources))
        resource['ResourcesMeanEntropy'] = sum(entropy)/float(len(entropy))
        resource['ResourcesMinEntropy'] = min(entropy)
        resource['ResourcesMaxEntropy'] = max(entropy)
        sizes = list(map(lambda x:x[1], resources))
        resource['ResourcesMeanSize'] = sum(sizes)/float(len(sizes))
        resource['ResourcesMinSize'] = min(sizes)
        resource['ResourcesMaxSize'] = max(sizes)
    else:
        resource['ResourcesNb'] = 0
        resource['ResourcesMeanEntropy'] = 0
        resource['ResourcesMinEntropy'] = 0
        resource['ResourcesMaxEntropy'] = 0
        resource['ResourcesMeanSize'] = 0
        resource['ResourcesMinSize'] = 0
        resource['ResourcesMaxSize'] = 0

    try:
        resource['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        resource['LoadConfigurationSize'] = 0

    try:
        version_infos = get_ver_info(pe)
        resource['VersionInformationSize'] = len(version_infos.keys())
    except AttributeError:
        resource['VersionInformationSize'] = 0
    return resource

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Detect malicious files')
    parser.add_argument('FILE', help='File to be tested')
    args = parser.parse_args()
    clf = joblib.load(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'classifier/classifier.pkl'
    ))
  
    with open('classifier/features.pkl', 'rb') as f:
        features = pickle.load(f)

    data = extract_infos(args.FILE)
    pe_features = list(map(lambda x:data[x], features))

    resource= clf.predict([pe_features])[0]
    print('The file %s is %s' % (
        os.path.basename(sys.argv[1]),
        ['malicious', 'legitimate'][resource])
    )
