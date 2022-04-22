import pefile
import os
import hashlib
import array
import math

def get_md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def get_entropy(data):
    if (len(data) == 0):
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
    resource = []
    resource.append(os.path.basename(fpath))
    resource.append(get_md5(fpath))
    pe = pefile.PE(fpath)
    resource.append(pe.FILE_HEADER.Machine)
    resource.append(pe.FILE_HEADER.SizeOfOptionalHeader)
    resource.append(pe.FILE_HEADER.Characteristics)
    resource.append(pe.OPTIONAL_HEADER.MajorLinkerVersion)
    resource.append(pe.OPTIONAL_HEADER.MinorLinkerVersion)
    resource.append(pe.OPTIONAL_HEADER.SizeOfCode)
    resource.append(pe.OPTIONAL_HEADER.SizeOfInitializedData)
    resource.append(pe.OPTIONAL_HEADER.SizeOfUninitializedData)
    resource.append(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    resource.append(pe.OPTIONAL_HEADER.BaseOfCode)
    try:
        resource.append(pe.OPTIONAL_HEADER.BaseOfData)
    except AttributeError:
        resource.append(0)
    resource.append(pe.OPTIONAL_HEADER.ImageBase)
    resource.append(pe.OPTIONAL_HEADER.SectionAlignment)
    resource.append(pe.OPTIONAL_HEADER.FileAlignment)
    resource.append(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
    resource.append(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
    resource.append(pe.OPTIONAL_HEADER.MajorImageVersion)
    resource.append(pe.OPTIONAL_HEADER.MinorImageVersion)
    resource.append(pe.OPTIONAL_HEADER.MajorSubsystemVersion)
    resource.append(pe.OPTIONAL_HEADER.MinorSubsystemVersion)
    resource.append(pe.OPTIONAL_HEADER.SizeOfImage)
    resource.append(pe.OPTIONAL_HEADER.SizeOfHeaders)
    resource.append(pe.OPTIONAL_HEADER.CheckSum)
    resource.append(pe.OPTIONAL_HEADER.Subsystem)
    resource.append(pe.OPTIONAL_HEADER.DllCharacteristics)
    resource.append(pe.OPTIONAL_HEADER.SizeOfStackReserve)
    resource.append(pe.OPTIONAL_HEADER.SizeOfStackCommit)
    resource.append(pe.OPTIONAL_HEADER.SizeOfHeapReserve)
    resource.append(pe.OPTIONAL_HEADER.SizeOfHeapCommit)
    resource.append(pe.OPTIONAL_HEADER.LoaderFlags)
    resource.append(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
    resource.append(len(pe.sections))
    entropy = map(lambda x:x.get_entropy(), pe.sections)
    resource.append(sum(entropy)/float(len(entropy)))
    resource.append(min(entropy))
    resource.append(max(entropy))
    raw_sizes = map(lambda x:x.SizeOfRawData, pe.sections)
    resource.append(sum(raw_sizes)/float(len(raw_sizes)))
    resource.append(min(raw_sizes))
    resource.append(max(raw_sizes))
    virtual_sizes = map(lambda x:x.Misc_VirtualSize, pe.sections)
    resource.append(sum(virtual_sizes)/float(len(virtual_sizes)))
    resource.append(min(virtual_sizes))
    resource.append(max(virtual_sizes))
    try:
        resource.append(len(pe.DIRECTORY_ENTRY_IMPORT))
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        resource.append(len(imports))
        resource.append(len(filter(lambda x:x.name is None, imports)))
    except AttributeError:
        resource.append(0)
        resource.append(0)
        resource.append(0)
    try:
        resource.append(len(pe.DIRECTORY_ENTRY_EXPORT.symbols))
    except AttributeError:
        resource.append(0)
    resources= get_resources(pe)
    resource.append(len(resources))
    if len(resources)> 0:
        entropy = map(lambda x:x[0], resources)
        resource.append(sum(entropy)/float(len(entropy)))
        resource.append(min(entropy))
        resource.append(max(entropy))
        sizes = map(lambda x:x[1], resources)
        resource.append(sum(sizes)/float(len(sizes)))
        resource.append(min(sizes))
        resource.append(max(sizes))
    else:
        resource.append(0)
        resource.append(0)
        resource.append(0)
        resource.append(0)
        resource.append(0)
        resource.append(0)

    try:
        resource.append(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size)
    except AttributeError:
        resource.append(0)

    try:
        ver_infos = get_ver_info(pe)
        resource.append(len(ver_infos.keys()))
    except AttributeError:
        resource.append(0)
    return resource

if __name__ == '__main__':
    output = "data.csv"
    csv_delimiter = "|"
    columns = [
        "Name",
        "md5",
        "Machine",
        "SizeOfOptionalHeader",
        "Characteristics",
        "MajorLinkerVersion",
        "MinorLinkerVersion",
        "SizeOfCode",
        "SizeOfInitializedData",
        "SizeOfUninitializedData",
        "AddressOfEntryPoint",
        "BaseOfCode",
        "BaseOfData",
        "ImageBase",
        "SectionAlignment",
        "FileAlignment",
        "MajorOperatingSystemVersion",
        "MinorOperatingSystemVersion",
        "MajorImageVersion",
        "MinorImageVersion",
        "MajorSubsystemVersion",
        "MinorSubsystemVersion",
        "SizeOfImage",
        "SizeOfHeaders",
        "CheckSum",
        "Subsystem",
        "DllCharacteristics",
        "SizeOfStackReserve",
        "SizeOfStackCommit",
        "SizeOfHeapReserve",
        "SizeOfHeapCommit",
        "LoaderFlags",
        "NumberOfRvaAndSizes",
        "SectionsNb",
        "SectionsMeanEntropy",
        "SectionsMinEntropy",
        "SectionsMaxEntropy",
        "SectionsMeanRawsize",
        "SectionsMinRawsize",
        "SectionMaxRawsize",
        "SectionsMeanVirtualsize",
        "SectionsMinVirtualsize",
        "SectionMaxVirtualsize",
        "ImportsNbDLL",
        "ImportsNb",
        "ImportsNbOrdinal",
        "ExportNb",
        "ResourcesNb",
        "ResourcesMeanEntropy",
        "ResourcesMinEntropy",
        "ResourcesMaxEntropy",
        "ResourcesMeanSize",
        "ResourcesMinSize",
        "ResourcesMaxSize",
        "LoadConfigurationSize",
        "VersionInformationSize",
        "legitimate"
    ]

    ff = open(output, "a")
    ff.write(csv_delimiter.join(columns) + "\n")

    for ffile in os.listdir('legitimate'):
        print(ffile)
        try:
            resource = extract_infos(os.path.join('legitimate/', ffile))
            resource.append(1)
            ff.write(csv_delimiter.join(map(lambda x:str(x), resource)) + "\n")
        except pefile.PEFormatError:
            print('\t -> Bad PE format')

    for ffile in os.listdir('malicious'):
        print(ffile)
        try:
            resource = extract_infos(os.path.join('malicious/', ffile))
            resource.append(0)

            ff.write(csv_delimiter.join(map(lambda x:str(x), resource)) + "\n")
        except pefile.PEFormatError:
            print('\t -> Bad PE format')
        except:
            print('\t -> Weird error')
    ff.close()
