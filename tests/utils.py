import json
import os

import yaml

dir_path = os.path.dirname(os.path.realpath(__file__))
fixture_dir = f'{dir_path}/fixtures'


def get_fixture(file_name):
    """

    :param file_name:
    :type file_name: str
    :return:
    :rtype: str
    """
    with open(f'{fixture_dir}/{file_name}') as file_stream:
        return file_stream.read()


def get_json_fixture_as_dict(file_name):
    """

    :param file_name:
    :type file_name: str
    :return:
    :rtype: dict
    """
    with open(f'{fixture_dir}/{file_name}') as json_file:
        try:
            return json.loads(get_fixture(file_name))
        except json.JSONDecodeError as err:
            print(f'Error loading Fixture file: {file_name}\nError Message:\n{err}')


def get_json_fixture_as_string(file_name):
    """

    :param file_name:
    :type file_name:
    :return:
    :rtype: str
    """
    return json.dumps(get_json_fixture_as_dict(file_name))


def get_yaml_fixture(file_name):
    """

    :param file_name:
    :type file_name:
    :return:
    :rtype: dict
    """
    with open(f'{fixture_dir}/{file_name}') as yaml_file:
        try:
            fixture_content = yaml.load(yaml_file, Loader=yaml.FullLoader)
        except yaml.YAMLError as err:
            print(f'Error loading Fixture file: {file_name}\nError Message:\n{err}')

    return fixture_content
