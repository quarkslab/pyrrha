# -*- coding: utf-8 -*-

#  Copyright 2023 Quarkslab
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from pathlib import Path

import sourcetraildb


class DBInterface:
    """TODO, rappeler obligation de init et close + commit"""

    def __init__(self, db_path: Path, clear_db: bool = True):
        """
        Initialize the interface with the DB used by sourcetrail.
        :param db_path: path of the db file, will create it if it does not exist
        :param clear_db: if the DB should be cleared or not, default = true
        """
        if db_path.suffix != '.srctrldb':
            db_path = db_path.with_suffix('.srctrldb')
        self.db_path = db_path
        sourcetraildb.open(str(self.db_path))
        if clear_db:
            sourcetraildb.clear()
        sourcetraildb.beginTransaction()

    @staticmethod
    def close():
        """
        Close the connection to the DB after committing the last changes done by the user.
        """
        sourcetraildb.commitTransaction()
        sourcetraildb.close()

    @staticmethod
    def __create_name_element_from_path(path: Path) -> str:
        """Uniformize the name elements used to represent paths"""
        return f'{{ "prefix": "{path.parent}/", "name": "{path.name}", "postfix": "" }} '

    @staticmethod
    def __create_name_element_from_name(symbol_name: str) -> str:
        """Uniformize the name elements used to represent paths"""
        return f'{{ "prefix": "", "name": "{symbol_name}", "postfix": "" }} '

    @staticmethod
    def __record_class(name_element: str) -> int:
        """
        Record a class symbol inside the current open DB.
        This DB should be already open.
        :param name_element: name element of the class as a JSON str of the form
            f'{ "prefix": "class", "name": "MY NAME", "postfix": "()" }'
            (prefix and postfixs are not mandatory)
        :return: unique identifier of the created object inside the DB
        """
        cls_id = sourcetraildb.recordSymbol(
            f'{{"name_delimiter": ":", "name_elements": [ {name_element}] }}')
        sourcetraildb.recordSymbolKind(cls_id, sourcetraildb.SYMBOL_CLASS)
        sourcetraildb.recordSymbolDefinitionKind(cls_id, sourcetraildb.DEFINITION_EXPLICIT)
        return cls_id

    @staticmethod
    def __record_typedef(name_element: str) -> int:
        """
        Record a typedef symbol inside the current open DB.
        This DB should be already open.
        :param name_element: name element of the typedef as a JSON str of the form
            f'{ "prefix": "void", "name": "MY NAME", "postfix": "()" }'
            (prefix and postfixs are not mandatory)
        :return: unique identifier of the created object inside the DB
        """
        cls_id = sourcetraildb.recordSymbol(
            f'{{"name_delimiter": ":", "name_elements": [ {name_element}] }}')
        sourcetraildb.recordSymbolKind(cls_id, sourcetraildb.SYMBOL_TYPEDEF)
        sourcetraildb.recordSymbolDefinitionKind(cls_id, sourcetraildb.DEFINITION_EXPLICIT)
        return cls_id

    @staticmethod
    def __record_method(class_name_element: str, method_name_element: str) -> int:
        """
        Record a typedef symbol inside the current open DB.
        This DB should be already open.
        :param class_name_element: name element of the parent class as a JSON str of the form
            f'{ "prefix": "void", "name": "MY NAME", "postfix": "()" }'
            (prefix and postfixs are not mandatory)
        :param method_name_element: name element of the method
        :return: unique identifier of the created object inside the DB
        """
        meth_id = sourcetraildb.recordSymbol(
            f'{{"name_delimiter": ":", "name_elements": [ {class_name_element}, {method_name_element}] }}')
        sourcetraildb.recordSymbolKind(meth_id, sourcetraildb.SYMBOL_METHOD)
        sourcetraildb.recordSymbolDefinitionKind(meth_id, sourcetraildb.DEFINITION_EXPLICIT)
        return meth_id

    @staticmethod
    def __record_field(class_name_element: str, field_name_element: str) -> int:
        """
        Record a field symbol inside the current open DB.
        This DB should be already open.
        :param class_name_element: name element of the parent class as a JSON str of the form
            f'{ "prefix": "void", "name": "MY NAME", "postfix": "()" }'
            (prefix and postfixs are not mandatory)
        :param field_name_element: name element of the field
        :return: unique identifier of the created object inside the DB
        """
        field_id = sourcetraildb.recordSymbol(
            f'{{"name_delimiter": ":", "name_elements": [ {class_name_element}, {field_name_element}] }}')
        sourcetraildb.recordSymbolKind(field_id, sourcetraildb.SYMBOL_METHOD)
        sourcetraildb.recordSymbolDefinitionKind(field_id, sourcetraildb.DEFINITION_EXPLICIT)
        return field_id

    def record_binary_file(self, file_path: Path) -> int:
        """
        Add a representation of binary file into the DB
        :param file_path: path of the file (inside the firmware)
        :return: the uniq identifier of the file
        """
        return self.__record_class(self.__create_name_element_from_path(file_path))

    def record_exported_symbol(self, file_path: Path, name: str, is_function: bool) -> int:
        """
        Add a representation of an exported symbol into the DB
        :param file_path: path of the binary/library (inside the firmware)
        :param name: symbol name
        :param is_function: True if the symbol is a function, else False
        :return: the uniq identifier of the exported symbol
        """
        if is_function:
            return self.__record_method(self.__create_name_element_from_path(file_path),
                                        self.__create_name_element_from_name(name))
        return self.__record_field(self.__create_name_element_from_path(file_path),
                                   self.__create_name_element_from_name(name))

    def record_symlink(self, symlink_path: Path) -> int:
        """
        Add a representation of a symlink into the DB
        :param symlink_path: path of the symlink to insert (inside the firmware)
        :return: the uniq identifier of the symlink
        """
        return self.__record_typedef(self.__create_name_element_from_path(symlink_path))

    @staticmethod
    def record_symlink_target(symlink_id: int, target_id: int) -> None:
        """
        Add a link between the symlink object and its target object.
        It is a reference with the type IMPORT.
        :param symlink_id: id of the symlink object inside db
        :param target_id: id of the symlink target object inside db
        """
        sourcetraildb.recordReference(symlink_id, target_id, sourcetraildb.REFERENCE_IMPORT)

    @staticmethod
    def record_import(current_object_id: int, imported_object_id: int) -> None:
        """
        Add a reference (with the type IMPORT) between the current object and
        the imported target object.
        :param current_object_id: object which import
        :param imported_object_id: imported object
        """
        sourcetraildb.recordReference(current_object_id,
                                      imported_object_id,
                                      sourcetraildb.REFERENCE_IMPORT)
