import xml.etree.ElementTree as ElementTree
import hashlib
import os
import yaml
import jsonschema
from pprint import PrettyPrinter

# TODO: Verify if all files from game are present resp['datafile']['game'][0]['rom']
# TODO: put results in CSV
# TODO: Convert dat file to indexed sqlite for easier querying


def check_config_exists() -> bool:
    return os.path.isfile('config.yml')


def create_config_file() -> None:
    config_template = {'dat_file_path': '', 'roms_dir_path': ''}
    with open('config.yml', 'w') as file:
        yaml.dump(config_template, file)


def load_config() -> dict:
    if check_config_exists():
        config = read_config_file()
        try:
            verify_config_file(config)
        except (jsonschema.ValidationError, ValueError) as e:
            print(f'config.yml file not valid. Please fill in paramemters and re-run. Details: {e}')
    else:
        create_config_file()
        print('Config file "config.yml" generated. Please enter parameters there and re-run this script.')
        exit(0)
    return config


def read_config_file() -> dict:
    with open('config.yml', 'r') as file:
        config = yaml.safe_load(file)
    return config


def verify_config_file(config) -> None:
    schema = {
        "type": "object",
        "properties": {
            "dat_file_path": {"type": "string"},
            "roms_dir_path": {"type": "string"},
        },
        "required": ['dat_file_path', 'roms_dir_path']
    }
    jsonschema.validate(config, schema)
    if not os.path.isdir(config['roms_dir_path']):
        raise ValueError(f'Directory "{config['roms_dir_path']}" does not exist. Verify path in config.yml.')
    if not os.path.isfile(config['dat_file_path']):
        raise ValueError(f'File "{config['dat_file_path']}" does not exist. Verify path in config.yml.')


def xml_to_dict(xml_file):
    tree = ElementTree.parse(xml_file)
    root = tree.getroot()

    def elem_to_dict(elem):
        d = {elem.tag: {} if elem.attrib else None}
        children = list(elem)
        if children:
            dd = {}
            for dc in map(elem_to_dict, children):
                for k, v in dc.items():
                    if k in dd:
                        if not isinstance(dd[k], list):
                            dd[k] = [dd[k]]
                        dd[k].append(v)
                    else:
                        dd[k] = v
            d = {elem.tag: dd}
        if elem.attrib:
            d[elem.tag].update(('@' + k, v) for k, v in elem.attrib.items())
        if elem.text:
            text = elem.text.strip()
            if children or elem.attrib:
                if text:
                    d[elem.tag]['#text'] = text
            else:
                d[elem.tag] = text
        return d

    return elem_to_dict(root)


def get_md5_hash(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def filter_by_region(game_dict, region):
    """Returns only games with given region in their name."""
    filtered_list = []
    for game in game_dict['datafile']['game']:
        if f'({region})' in game['@name']:
            filtered_list.append(game)
    return filtered_list


def get_discs(directory):
    """
    Returns a list of dictionaries with 'path' and 'filename' keys for all .bin and .cue files in the specified directory.

    :param directory: The directory to search for files.
    :return: A list of dictionaries with 'path' and 'filename' keys.
    """
    bin_cue_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.bin') or file.endswith('.cue'):
                file_info = {
                    'path': os.path.join(root, file),
                    'filename': file
                }
                bin_cue_files.append(file_info)
    return bin_cue_files


def lookup_disc_by_md5(discs, md5_hash, filename) -> list:
    matches = []
    for disc in discs:
        for track in disc['rom']:
            track_info = {'track_name': track['@name'], 'disc_name': disc['@name']}
            if track['@md5'] == md5_hash and track['@name'] == filename:
                return [track_info]
            elif track['@md5'] == md5_hash:
                matches.append(track_info)
    return matches


def verify_filename_match(filename, filenames_matching_hash) -> bool:
    if filenames_matching_hash and filenames_matching_hash[0]['track_name'] == filename:
        return True
    else:
        return False


def find_partial_match(local_filename, hash_matches) -> str:
    for hash_match in hash_matches:
        if hash_match['disc_name'] in local_filename:
            return hash_match['track_name']
    return ''


def verify_file(local_file: dict, game_hashes) -> dict:
    ret = {'local_filename': local_file['filename'], 'md5_filename': '', 'alternate_filenames': []}
    md5_hash = get_md5_hash(local_file['path'])
    hash_matches = lookup_disc_by_md5(game_hashes, md5_hash, local_file['filename'])
    filename_match = verify_filename_match(local_file['filename'], hash_matches)
    if filename_match:
        ret['md5_filename'] = hash_matches[0]['track_name']
    else:
        partial_match = find_partial_match(local_file['filename'], hash_matches)
        if partial_match:
            ret['md5_filename'] = partial_match
        ret['alternate_filenames'] = hash_matches
    ret['filename_match'] = filename_match
    ret['md5_match'] = bool(hash_matches)
    return ret


def main():
    config = load_config()
    resp = xml_to_dict(config['dat_file_path'])
    usa_only = filter_by_region(resp, 'USA')
    discs = get_discs(config['roms_dir_path'])
    results = {'pass': {}, 'partial_pass': {}, 'fail': {}}
    for disc in discs:
        result = verify_file(disc, usa_only)
        if result['md5_match'] and result['filename_match']:
            results['pass'][result['local_filename']] = result
        elif result['md5_match']:
            results['partial_pass'][result['local_filename']] = result
        else:
            results['fail'][result['local_filename']] = result
    PrettyPrinter().pprint(results)


if __name__ == '__main__':
    main()