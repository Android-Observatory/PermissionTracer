#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from enum import Enum
import os
import re
import sys
import datetime
import ntpath
import json
import configparser
import tempfile
import hashlib
import pickle

config = configparser.ConfigParser()
config.read('config.ini')

if len(config.sections()) == 0:
    try:
        import androguard
    except:
        print("{ERROR} YOU MUST HAVE ANDROGUARD INSTALLED")
        sys.exit(1)

    from androguard.core.analysis.analysis import Analysis, ClassAnalysis, MethodAnalysis
    from androguard.core.analysis.analysis import FieldAnalysis
    from androguard.decompiler.decompiler import DecompilerDAD
    from androguard.misc import AnalyzeAPK
    from androguard.misc import AnalyzeDex

    # HARDCODED PATH TO DEXTRIPADOR
    sys.path = ["dextripador"] + sys.path

    from Dextripador import Extractor

else:
    androguard_path = ""
    dextripador_path = ""
    try:
        androguard_path = str(config['PATHS']['ANDROGUARD_PATH'])
        dextripador_path = str(config['PATHS']['DEXTRIPADOR_PATH'])
    except KeyError as ke:
        print("{ERROR} %s" % str(ke))
        sys.exit(1)

    sys.path = [androguard_path] + sys.path
    sys.path = [dextripador_path] + sys.path

    from androguard.core.analysis.analysis import Analysis, ClassAnalysis, MethodAnalysis
    from androguard.core.analysis.analysis import FieldAnalysis
    from androguard.decompiler.decompiler import DecompilerDAD
    from androguard.misc import AnalyzeAPK
    from androguard.misc import AnalyzeDex
    from androguard.core.analysis.analysis import ExternalClass
    from androguard.core.analysis.analysis import ExternalMethod
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.dvm_types import Kind
    from Dextripador import Extractor


DEBUG_FLAG = False
WARNING_FLAG = False
ERROR_FLAG = False
ANALYST_FLAG = False

FILE_OUTPUT = False
FILE_NAME = ""


class Debug:
    def __init__(self):
        ''' Constructor of Debug class '''

    @staticmethod
    def log(msg):
        ''' print debug messages '''
        if DEBUG_FLAG:
            print("{DEBUG} %s - %s" % (datetime.datetime.now(), msg))

    @staticmethod
    def analyst(msg):
        ''' print analyst messages '''
        if ANALYST_FLAG:
            print("{ANALYST} %s - %s" % (datetime.datetime.now(), msg))

    @staticmethod
    def warning(msg, error):
        ''' print warning messages '''
        if WARNING_FLAG:
            print("{WARNING} %s - %s: %s" %
                  (datetime.datetime.now(), msg, str(error)))

    @staticmethod
    def error(msg, error, exception):
        ''' print error messages '''
        if ERROR_FLAG:
            print("{ERROR} %s - %s: %s" %
                  (datetime.datetime.now(), msg, str(error)))
        raise exception(msg)

class StringAnalyzer:

    def __init__(self, analysis_object: Analysis, class_object: ClassAnalysis, file_path: str = None):
        """
        Constructor of StringAnalyzer this class will
        get all the strings from the class wherever this
        strings come from (static fields, method names,
        class names, strings in the code), then we will
        try to match them with those from a specified file.
        
        :param analysis_object: Analysis object to get all the strings from the apk.
        :param class_object: ClassAnalysis object to get the information from the class.
        :param file_path: path to the file with the list of strings to search.
        """
        self.class_name = str(class_object.name)
        self.method_names = set()
        self.field_names = set()
        self.strings = set()

        for method in class_object.get_methods():
            self.method_names.add(str(method.name))

        for field in class_object.get_fields():
            self.field_names.add(str(field.name))

        for string in analysis_object.get_strings():
            string_xrefs = string.get_xref_from()
            for xref in string_xrefs:
                if str(xref[0].name) == self.class_name:
                    self.strings.add(str(string.get_orig_value()))
                    break
        
        self.strings = self.strings - self.field_names
        self.strings = self.strings - self.method_names
        self.strings = self.strings - set(self.class_name)

        self.keywords = set()

        if file_path and len(file_path) > 0:
            with open(file_path, 'r') as keys_file:
                for line in keys_file.readlines():
                    self.keywords.add(line.strip().replace('\n',''))
            
    def analyze_class_name(self):
        """
        Search in the class name all the keywords and get the index.

        :return: dict
        """
        return_value = {"class_string_analysis": dict()}

        for keyword in self.keywords:
            if keyword.lower() in self.class_name.lower():
                return_value["class_string_analysis"] = {self.class_name:dict()}
                return_value["class_string_analysis"][self.class_name][keyword] = {"index": self.class_name.lower().index(keyword.lower())}

        return return_value

    def analyze_methods(self):
        """
        Search in all the method names all the keywords and get the index.

        :return: dict
        """
        return_value = {"method_string_analysis": dict()}

        for method in self.method_names:
            for keyword in self.keywords:
                if keyword.lower() in method.lower():
                    return_value["method_string_analysis"] = {method:dict()}
                    return_value["method_string_analysis"][method][keyword] = {}
                    return_value["method_string_analysis"][method][keyword] = {"index": method.lower().index(keyword.lower())}

        return return_value

    def analyze_fields(self):
        """
        Search in all the field names all the keywords and get the index.

        :return: dict
        """
        return_value = {"field_string_analysis": dict()}

        for field in self.field_names:
            for keyword in self.keywords:
                if keyword.lower() in field.lower():
                    return_value["field_string_analysis"] = {field:dict()}
                    return_value["field_string_analysis"][field][keyword] = {}
                    return_value["field_string_analysis"][field][keyword] = {"index": field.lower().index(keyword.lower())}

        return return_value
    
    def analyze_strings(self):
        """
        Search in all the raw strings all the keywords and get the index.

        :return: dict
        """
        return_value = {"raw_String_analysis": dict()}

        for string in self.strings:            
            for keyword in self.keywords:
                if keyword.lower() in string.lower():
                    return_value["raw_String_analysis"] = {string:dict()}
                    return_value["raw_String_analysis"][string][keyword] = {}
                    return_value["raw_String_analysis"][string][keyword] = {"index": string.lower().index(keyword.lower())}
                
        return return_value


class IntentFilterAnalyzer:
    # Supported component types for analysis

    class ComponentTypes(Enum):
        """
        Components that we support (or going to support)
        this will be written as an Enum value starting 
        from 1, and ending in 99 that means is something
        we do not support.
        """
        ACTIVITY = 1
        SERVICE = 2
        PROVIDER = 3
        RECEIVER = 4
        NOT_SUPPORTED = 99

        def __str__(self) -> str:
            if self.value == 1:
                return "Activity"
            elif self.value == 2:
                return "Service"
            elif self.value == 3:
                return "Content provider"
            elif self.value == 4:
                return "Broadcast receiver"
            else:
                return "Not Supported"

    def __init__(self, apk_analysis: Analysis, apk: APK, classes_dex: list):
        """
        Constructor method for IntentFilterAnalyzer, initialization
        of variables is done here.

        :param apk_analysis: object Analysis returned by Androguard.
        :param apk: object APK returned by Androguard.
        :return: None
        """
        self.apk_analysis = apk_analysis
        self.apk = apk
        self.classes_dex = classes_dex
        self.decompiler = DecompilerDAD(classes_dex, apk_analysis)
        self.exposed_methods = {}
        self.data_provided = {}
        self.component_type = {}

    '''
    Generic methods, use them in your analysis implementation
    also feel free to include whatever generic method you want,
    following always the programming convention followed, parameters
    include the type of the parameter, and the comment of each
    method should describe what the method does, the parameters and
    the return type.
    Names for private methods will be written starting with '_'.
    '''

    def _extract_component_type(self, class_name: str):
        """
        Method to extract the type of the class name given,
        depending on the analysis that we support, we will
        return a given value.

        :param class_name: str with the class name to categorize.
        :return: ComponentTypes
        """

        # clean the name and rewrite it properly to search
        # it in the manifest file
        if class_name[0] == 'L':
            class_name = class_name[1:]

        if class_name[-1] == ';':
            class_name = class_name[:-1]

        class_name = class_name.replace('/', '.')

        if class_name in self.apk.get_activities():
            return self.ComponentTypes.ACTIVITY

        if class_name in self.apk.get_services():
            return self.ComponentTypes.SERVICE

        if class_name in self.apk.get_providers():
            return self.ComponentTypes.PROVIDER

        if class_name in self.apk.get_receivers():
            return self.ComponentTypes.RECEIVER

        return self.ComponentTypes.NOT_SUPPORTED

    def _get_class_from_analysis(self, class_name: str):
        """
        Return a ClassAnalysis object from a given class name inside
        of the analysis object.
        Format of class_name must be:
            "L<class_name>;"

        :param class_name: str with class name to obtain object.
        :return: ClassAnalysis
        """
        for class_ in self.apk_analysis.get_classes():
            if str(class_.name) == class_name:
                Debug.log("Found class '%s'" % (class_name))
                return class_

        return None

    def _get_method_from_class_object(self, class_object: ClassAnalysis, method_name: str):
        """
        Return a Method object from a given method name from
        a specific class.

        :param class_object: ClassAnalysis object where to search the method.
        :param method_name: method to look for.
        :return: MethodAnalysis
        """
        for method in class_object.get_methods():
            if str(method.name) == method_name:
                Debug.log("Found method '%s'" % (method_name))
                return method

        return None

    def _get_types_as_list(self, types_str: str):
        """
        Get the smali types of a string as a list of
        types, we will parse it as a list of types.

        :parameter types_str: string with a list of types (it can be just one).
        :return: list
        """
        types_list = []
        types_str = types_str.replace('(', '').replace(')', '')

        len_types_str = len(types_str)

        is_object = False
        is_array = False
        start_index = 0

        for i in range(len_types_str):

            if is_object:
                if types_str[i] == ';':
                    is_object = False
                    if not is_array:
                        types_list.append(str(types_str[start_index:i+1]))
                    else:
                        types_list.append(
                            str(types_str[start_index:i+1]) + "[]")
                        is_array = False
                else:
                    continue

            if types_str[i] == 'Z':
                if not is_array:
                    types_list.append('boolean')
                else:
                    types_list.append('boolean[]')
                    is_array = False
            elif types_str[i] == 'B':
                if not is_array:
                    types_list.append('byte')
                else:
                    types_list.append('byte[]')
                    is_array = False
            elif types_str[i] == 'C':
                if not is_array:
                    types_list.append('char')
                else:
                    types_list.append('char[]')
                    is_array = False
            elif types_str[i] == 'D':
                if not is_array:
                    types_list.append('double')
                else:
                    types_list.append('double[]')
                    is_array = False
            elif types_str[i] == 'F':
                if not is_array:
                    types_list.append('float')
                else:
                    types_list.append('float[]')
                    is_array = False
            elif types_str[i] == 'I':
                if not is_array:
                    types_list.append('integer')
                else:
                    types_list.append('integer[]')
                    is_array = False
            elif types_str[i] == 'J':
                if not is_array:
                    types_list.append('long')
                else:
                    types_list.append('long[]')
                    is_array = False
            elif types_str[i] == 'S':
                if not is_array:
                    types_list.append('short')
                else:
                    types_list.append('short[]')
                    is_array = False
            elif types_str[i] == 'V':
                if not is_array:
                    types_list.append('void')
                else:
                    types_list.append('void[]')
                    is_array = False
            elif types_str[i] == 'L':
                is_object = True
                start_index = i
            elif types_str[i] == '[':
                is_array = True

        return types_list

    def _get_references_to_method(self, method_object: MethodAnalysis, class_name: str):
        """
        Method to get all the cross references from a
        method object, the class name must appear in
        the cross reference in order to be included.

        :param method_object: method of which we will extract the cross references.
        :param class_name: only the cross references done from this class will be retrieved.
        :return: list of cross references.
        """
        xrefs = []
        all_xrefs = method_object.get_xref_from()

        for _, call, _ in all_xrefs:
            if class_name in str(call.class_name):
                Debug.log("Found xrefs to %s from %s->%s" %
                          (str(method_object.name), str(call.class_name), str(call.name)))
                xrefs.append(call)

        return xrefs

    def _get_intent_actions(self, class_name: str, component_type: str):
        '''
        Method to retrieve from the AndroidManifest all the action
        names that the class will respond to. We will focus on those
        actions from AOSP. These together with the return types
        could be useful to see what data is retrieved from a component.

        :param class_name: class to search in the manifest to retrieve the intent actions.
        :param component_type: string with type of the component.
        :return: list[str]
        '''
        element = self.apk.get_android_manifest_xml()
        application = element.find('application')

        actions = set()

        component_to_analyze = None

        class_name = class_name.replace('/', '.')[1:-1]

        for component in application.findall(component_type):
            if component.attrib['{http://schemas.android.com/apk/res/android}name'] == class_name:
                component_to_analyze = component
                break

        if component_to_analyze is None:
            return []

        for intent_filter in component_to_analyze.findall('intent-filter'):
            for action in intent_filter.findall('action'):
                actions.add(
                    action.attrib['{http://schemas.android.com/apk/res/android}name'])

        return list(actions)

    '''
    Methods to analyze methods exported by a service
    in order to get what a Service "could" leak through
    an intent.
    '''

    def _analyze_assignment(self, assignment_node: list, field_name: str):
        '''
        Analyze the Assignment statements from Androguard AST
        here we will extract which type of object is assigned
        to given field. This is necessary as Java can use base
        classes and access different methods due to polymorphism.

        :param assignment_node: node from the AST to analyze.
        :param field_name: field that we look for.
        :return: class name of object assigned to field, None if not found.
        '''
        left_part = assignment_node[0]
        right_part = assignment_node[1]

        # check left part of the assignment instruction
        # this must be a FieldAccess and the field must be
        # the one we are looking for
        if left_part[0] != "FieldAccess" or \
                str(left_part[2][1]) != field_name:
            return None

        # analyze right part, for the moment check for ClassInstanceCreation
        if right_part[0] == "ClassInstanceCreation" and \
                right_part[-1][0] == "TypeName":
            Debug.log("Found assignment to '%s' with object from class '%s'" % (
                field_name, right_part[-1][1][0]))
            return str(right_part[-1][1][0])

        return None

    def _find_assignments(self, node: list, field_name: str):
        '''
        Given an ExpressionStatement node check if current
        node is an Assignment from AST.

        :param node: list with node currently analyzed.
        :param field_name: field that we look for.
        :return: class name of object assigned to field, None if not found.
        '''
        Debug.log("Analyzing node type '%s'" % (node[0]))
        if node[0] == 'Assignment':
            # analyze
            return self._analyze_assignment(node[1], field_name)

        else:
            return None

    def _analyze_blockstatement(self, node: list, field_name: str):
        """
        Analyze all the statements of a BlockStatement, we will
        just take those that are ExpressionStatement and we will
        use it to find specific Assignment statements.

        :param node: list with all the statements from a BlockStatement
        :param field_name: field that we look for.
        :return: list with all classes assigned to a given field.
        """
        ret_list = set()
        for expression_statement in node:
            if expression_statement[0] != 'ExpressionStatement':
                continue

            ret_val = self._find_assignments(
                expression_statement[-1], field_name)

            if ret_val is not None:
                ret_list.add(ret_val)

        return list(ret_list)

    def _get_class_from_object_instantiation(self, field_object: FieldAnalysis):
        """
        Given a field, we will try to obtain through its references
        where is initialized and which object instantiate this field/variable.
        For example:

        `android.os.Binder` is a base class that programmers extend to create
        an interface than another application or component from same application
        can use to call methods. So we get the uses of `android.os.Binder` and
        see where is instantiated and from those, which one correspond to the
        variable name.

        :param field_object: Field that we will analyze to get its references and obtain the real object
        :return: [ClassAnalysis]
        """
        instantiated_classes = set()
        field_references = field_object.get_xref_write(True)

        for _, method_, _ in field_references:

            encoded_method = method_.get_method()

            method_ast = self.decompiler.get_ast_method(encoded_method)

            method_body = method_ast['body']

            if method_body[0] == 'BlockStatement':
                instantiated_classes.update(self._analyze_blockstatement(
                    method_body[-1], str(field_object.name)))

        return list(instantiated_classes)

    def _get_method_returned_classes(self, method_object: MethodAnalysis):
        '''
        Methods such as onBind are used by Services to return a Bind object
        that other Applications or Activities can use in order to call Service
        methods and retrieve information. Another example is the method
        onReceive in broadcasts receivers.
        This method will return all the returned classes from these methods.

        :param method_object: MethodAnalysis of the onBind method.
        :return: list[ClassAnalysis]
        '''
        method_instructions = []
        classes_returned_by_method = []

        for block in method_object.get_basic_blocks():
            for inst in block.get_instructions():
                method_instructions.append(inst)

        for i in range(len(method_instructions)):
            # look for all the return instructions in order
            # to retrieve all the returned types!
            inst = method_instructions[i]

            if inst.get_op_value() == 0x11:
                Debug.log("Found instruction return-object: '%s'" %
                          (inst.disasm()))

                # retrieve the operand
                if len(inst.get_operands()) > 1:
                    # operands for return object should be just one
                    continue

                if inst.get_operands()[0][0].name != 'REGISTER':
                    # we look for registers
                    continue

                reg_number = inst.get_operands()[0][1]

                Debug.log("Register number used: %d" % (reg_number))

                class_object = None

                # start backward analysis
                for j in range(i, -1, -1):
                    # check for iget-object
                    if method_instructions[j].get_op_value() != 0x54:
                        continue

                    # check that where object is stored is a register
                    if method_instructions[j].get_operands()[0][0].name != 'REGISTER':
                        continue
                    # check is the one we want to find
                    if method_instructions[j].get_operands()[0][1] != reg_number:
                        continue

                    class_return_str = method_instructions[j].get_operands()[
                        2][2]
                    # "where_is_stored->var_name var_type"
                    # retrieve only the var_type
                    base_class = class_return_str.split('->')[0]
                    field_name = class_return_str.split('->')[1].split(' ')[0]

                    # get class of returned object
                    class_return_str = class_return_str.split(' ')[1]

                    # try to obtain a ClassAnalysis from its name
                    class_object = self._get_class_from_analysis(
                        class_return_str)

                    # if no class object were returned or is part of Android AOSP
                    if class_object is None or class_object.is_android_api() or class_object.is_external():
                        # Improved the analysis, commonly an android.os.Binder is returned
                        # but this is extended with other classes, try to get those classes:

                        # Obtain the field object for this variable
                        # this field object will allow us to obtain
                        # cross references to know where is written.
                        fields = self._get_class_from_analysis(
                            base_class).get_fields()
                        
                        field_for_analysis = None
                        
                        for f in fields:
                            if str(f.name) == field_name:
                                field_for_analysis = f
                                break

                        if field_for_analysis is None:
                            class_object = None
                        else:
                            returned_value = self._get_class_from_object_instantiation(
                                field_for_analysis)
                            if len(returned_value) > 0:
                                class_object = self._get_class_from_analysis(
                                    "L" + returned_value[0] + ";")
                            else:
                                class_object = None
                    else:
                        Debug.log("Found class instance returned by method '%s'" % (
                            str(class_object.name)))

                    break

                # Once finished, check if we can add it
                if class_object is not None:
                    classes_returned_by_method.append(class_object)

        return classes_returned_by_method

    def _get_types_from_set_result(self, method_object: MethodAnalysis, class_name: str):
        '''
        The method setResult from the Intent is used to return data from an
        Activity or BroadcastReceiver called (also through an intent) through
        the intent extras, this method does a backward analysis of the calls
        to setResult to extract all the extras. The output of the method will
        return a list of dictionaries being each key the name of the extra
        and the value is the type the extra returns.

        :param method_object: MethodAnalysis of the setResult method.
        :param class_name: class where to find for references to the method.
        :return: list[dict]
        '''
        method_xrefs = self._get_references_to_method(
            method_object=method_object, class_name=class_name)
        return_values = []

        if len(method_xrefs) == 0:
            return []

        for method in method_xrefs:
            # analyze the method where 'setResult' is called.
            method_instructions = []
            for block in method.get_basic_blocks():
                for inst in block.get_instructions():
                    method_instructions.append(inst)

            for i in range(len(method_instructions)):
                # look for an invoke-virtual instruction
                # of the setResult method.
                inst = method_instructions[i]

                # get those invoke-virtual
                # with operands
                # where the called function is setResult
                # and finally it contains and intent (return results)
                if inst.get_op_value() == 0x6e and \
                    len(inst.get_operands()) > 0 and \
                    'setResult' in str(inst.get_operands()[-1][-1]) and \
                        '(I Landroid/content/Intent;)' in str(inst.get_operands()[-1][-1]):

                    Debug.log(
                        "Found instruction invoke-virtual instruction: '%s'" % (inst.disasm()))

                    intent_register = inst.get_operands()[-2][1]
                    Debug.log("Register with intent: '%d'" % (intent_register))

                    # start backward analysis
                    for j in range(i, -1, -1):
                        if method_instructions[j].get_op_value() == 0x6e and \
                            len(method_instructions[j].get_operands()) > 0 and \
                                'putExtra' in str(method_instructions[j].get_operands()[-1][-1]):

                            # if the intent is not the one we want...
                            # leave
                            if method_instructions[j].get_operands()[0][1] != intent_register:
                                break

                            put_extra_type = self._get_types_as_list(
                                method_instructions[j].get_operands()[-1][-1].split('(')[1].split(')')[0])[-1]
                            key = ""

                            # search for the key in previous instructions
                            # for the moment support const-string need to
                            # add support for other ways to get strings
                            if method_instructions[j-1].get_op_value() == 0x1a:
                                key = str(
                                    method_instructions[j-1].get_operands()[-1][-1])
                            elif method_instructions[j-2].get_op_value() == 0x1a:
                                key = str(
                                    method_instructions[j-2].get_operands()[-1][-1])
                            elif method_instructions[j-3].get_op_value() == 0x1a:
                                key = str(
                                    method_instructions[j-3].get_operands()[-1][-1])

                            Debug.log(
                                "Found 'putExtra' call with key-type: '%s'-'%s'" % (key, put_extra_type))

                            return_values.append({key: put_extra_type})

        return return_values

    def _analyze_service(self, class_name: str):
        """
        Method to analyze a Service, we will analyze Remote
        Bound Services in order to discover onBind method, 
        retrieve the returned object and finally retrieve all
        the method prototypes.

        :param class_name: str with class name to extract information.
        :return: List
        """

        class_object = self._get_class_from_analysis(class_name)
        method_prototypes = []
        method_hashes = []


        if class_object is None:
            return []

        # Search for onBind method
        method_object = self._get_method_from_class_object(
            class_object=class_object, method_name="onBind")

        if method_object is None:
            return []

        returned_classes = self._get_method_returned_classes(
            method_object=method_object)

        # we have in returned classes a list of classes that
        # are returned by onBind method
        for class_ in returned_classes:
            for method in class_.get_methods():
                # REMOVED FOR THE MOMENT
                # if method.is_external():
                # as the returned classes are interfaces
                # return the external methods
                descriptor = method.descriptor

                # get the return type
                ret_type = self._get_types_as_list(
                    descriptor.split(')')[1])[0]
                parameters = self._get_types_as_list(
                    descriptor.split(')')[0])

                # avoid copies taking care of name of method
                # parameters and strings
                str_hash = str(method.name)

                for param in parameters:
                    str_hash += str(param)
                
                str_hash += str(ret_type)

                hash_ = hash(str_hash)

                if hash_ not in method_hashes:
                    method_prototypes.append(
                        {str(method.name): {
                            "return-type": ret_type,
                            "parameters": parameters
                        }}
                    )

                    method_hashes.append(hash_)

        return method_prototypes

    def _analyze_content_provider(self, class_name: str):
        """
        Method to analyze a Content Provider.
        It analyzes the `getType()` method which allows other apps to access
        whatever data is provided, and returns the type of data available.

        :param class_name: str with class name to extract information.
        :return: List
        """

        class_object = self._get_class_from_analysis(class_name)
        returned_data_types = []

        if class_object is None:
            return []

        # Search for getType method
        get_type_method_object = self._get_method_from_class_object(
            class_object=class_object, method_name="getType")

        if get_type_method_object is None:
            return []

        method_instructions = []

        for block in get_type_method_object.get_basic_blocks():
            for inst in block.get_instructions():
                method_instructions.append(inst)

        registers = dict()
        for i in range(len(method_instructions)):
            inst = method_instructions[i]

            if inst.get_op_value() == 0x1a:
                Debug.log("Found instruction const-string: '%s'" %
                          (inst.disasm()))
                register_index = inst.get_operands()[0][1]
                register_string = inst.get_operands()[1][2]
                registers[register_index] = register_string

            if inst.get_op_value() == 0x11:
                Debug.log("Found instruction return-object: '%s'" %
                          (inst.disasm()))
                register_index = inst.get_operands()[0][1]
                try:
                    Debug.log("Returned string at register v%d" %
                              register_index)
                    returned_data_types.append(registers[register_index])
                except KeyError:
                    Debug.log("Error: no string at register v%d" %
                              register_index)

        return returned_data_types

    def _analyze_broadcast_receiver(self, class_name: str):
        """
        Method to analyze a broadcast receiver.
        In the same way than with Activities, 

        :param class_name: str with class name to extract information.
        :return: List
        """

        class_object = self._get_class_from_analysis(class_name)
        return_vaues = []

        if class_object is None:
            return []

        # Search for onReceive method
        method_object = self._get_method_from_class_object(
            class_object=class_object, method_name="setResult")

        if method_object is None:
            return []

        return_vaues = self._get_types_from_set_result(
            method_object=method_object, class_name=class_name)

        return return_vaues

    def _analyze_activity(self, class_name: str):
        """
        Method to analyze Activities exported by
        an application, in the case of the Activities
        this must be called with 'startActivityForResult'
        and then in the called activity the method
        'setResult' must be called with an intent as second
        parameter, containing this intent data extra with
        the variables.

        :param class_name: str with class name to extract information.
        :return: List
        """

        class_object = self._get_class_from_analysis(class_name)
        return_values = []

        if class_object is None:
            return []

        method_object = self._get_method_from_class_object(
            class_object=class_object, method_name="setResult")

        if method_object is None:
            return []

        return_values = self._get_types_from_set_result(
            method_object=method_object, class_name=class_name)

        return return_values

    def analyze_class(self, class_name: str):
        """
        Main method of the class, in this method we will analyze
        the class, and we will extract all the method prototypes.

        :param class_name: str with the class name to categorize.
        :return: List
        """
        Debug.log("Starting the analysis of the class '%s'" % (class_name))

        component_type = self._extract_component_type(class_name)
        Debug.log("Component type to analyze is '%s'" % (str(component_type)))

        if component_type == self.ComponentTypes.ACTIVITY:
            self.exposed_methods = {'interface': {},
                                    'intent-filter_actions': self._get_intent_actions(class_name, 'activity')}
            self.data_provided = {
                'data_provided': self._analyze_activity(class_name)}
        elif component_type == self.ComponentTypes.SERVICE:
            self.exposed_methods = {
                'interface': self._analyze_service(class_name),
                'intent-filter_actions': self._get_intent_actions(class_name, 'service')}
            self.data_provided = {'data_provided': {}}
        elif component_type == self.ComponentTypes.PROVIDER:
            self.exposed_methods = {'interface': {},
                                    'intent-filter_actions': self._get_intent_actions(class_name, 'provider')}
            cp_data_type = self._analyze_content_provider(class_name)
            length = len(cp_data_type)
            self.data_provided = {'data_provided': {
                'cp_data_{}'.format(i): cp_data_type[i] for i in range(0, length)}}
        elif component_type == self.ComponentTypes.RECEIVER:
            self.exposed_methods = {
                'interface': {},
                'intent-filter_actions': self._get_intent_actions(class_name, 'receiver')}
            self.data_provided = {
                'data_provided': self._analyze_broadcast_receiver(class_name)}
        else:
            self.exposed_methods = {'interface': {}}
            self.data_provided = {'data_provided': {}}

        return self.exposed_methods, self.data_provided, {'component_type': str(component_type)}


class PermissionTracer:

    def __init__(self, APK, md5, key_file: str = None):
        """
        Constructor method for PermissionTracer class, it will store and
        initialize variables, also it will call some starting methods.

        :param APK: path to the apk to analyze
        :param class_name_to_analyze: class where is the method to analyze
        :return: None
        """
        self.MAX_DEPTH = 7          # constant value
        self.apk = None             # value that must be set only once by __androguard_open_apk
        self.classes_dex = None     # value that must be set only once by __androguard_open_apk
        self.analysis = None        # value that must be set only once by __androguard_open_apk
        self.analysis_ok = False    # value that must be set only once by __androguard_open_apk
        self._md5 = md5
        self.intent_filter_analyzer = None
        self.string_analyzer = None
        self.key_file = key_file

        self.__androguard_open_apk(APK)

        if self.analysis_ok:
            self.intent_filter_analyzer = IntentFilterAnalyzer(
                apk_analysis=self.analysis, apk=self.apk, classes_dex=self.classes_dex)

    def __read_md5_odex_file(self):
        return pickle.load(open(config['PATHS']['MD5-ODEX-PICKLE'], 'rb'))

    def __calculate_md5(self, fname):
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def __set_variables(self):
        """
        Function to set variables to empty values once
        per execution of new class

        :return:
        """
        self.external_classes = list()
        self.analyzed_methods = []
        self.permission_analysis = {}
        self.method_object_start = []
        self.class_name = ""

    def __androguard_analyze_apk(self, path_to_file):
        """
        Wrapper of androguard AnalyzeAPK, it will also use the library
        extractor from dextripador if there's no class, we will try to
        get the odex from same path, if it doesn't exist... No dex analysis

        :param path_to_file: file to analyze
        :return: An APK object, array of DalvikVMFormat, and Analysis object
        """
        Debug.log("Analyzing file \"%s\"" % (path_to_file))

        apk, classes_dex, analysis = AnalyzeAPK(path_to_file)

        if len(classes_dex) == 0:
            Debug.warning("Warning, class.dex file not present, looking for odex to extract it",
                          FileNotFoundError("File classes.dex not found in %s" % path_to_file))

            path_to_odex = path_to_file.replace('.apk', '.odex')
            odex_file_name = path_to_odex.split('/')[-1]
            extractor = None

            if not os.path.isfile(path_to_odex):
                path_to_odex = '/'.join(path_to_file.split('/')
                                        [:-1]) + '/arm/' + odex_file_name
            if not os.path.isfile(path_to_odex):
                path_to_odex = '/'.join(path_to_file.split('/')
                                        [:-1]) + '/arm64/' + odex_file_name
            if not os.path.isfile(path_to_odex):
                path_to_odex = '/'.join(path_to_file.split('/')
                                        [:-1]) + '/oat/arm/' + odex_file_name
            if not os.path.isfile(path_to_odex):
                path_to_odex = '/'.join(path_to_file.split('/')
                                        [:-1]) + '/oat/arm64/' + odex_file_name

            if not os.path.isfile(path_to_odex):
                Debug.warning("odex file not found in the apk directory, computing md5 and looking in the list",
                              FileNotFoundError("odex file not found in directory"))
                # Lookup the list of MD5-ODEX

                # If no md5 is provided by command line, calculate it
                if self._md5 == '':
                    self._md5 = self.__calculate_md5(path_to_file)

                self.odex_md5_dict = self.__read_md5_odex_file()

                if (self._md5 in self.odex_md5_dict):
                    path_to_odex = self.odex_md5_dict[self._md5]
                    Debug.log("Found odex for md5=%s in the list. Path:%s" %
                              (self._md5, path_to_odex))
                else:
                    Debug.warning("odex file for hash %s not present in the list. Looking in the apk directory" %
                                  self._md5, FileNotFoundError("odex file for %s not found in list" % self._md5))
                    raise FileNotFoundError(
                        "odex file not found neither in directory nor by md5")

            extractor = Extractor(path_to_odex)
            extractor.load()
            fo = tempfile.NamedTemporaryFile()
            fo.close()  # we're just interested in the name
            if len(extractor.get_dex_files()) > 0:
                Debug.log("Extracting dex from odex to %s" %
                          (fo.name + '.dex'))
                if extractor.extract_dex(0, fo.name + ".dex", True):
                    # now try to analyze with androguard
                    _, classes_dex, analysis = AnalyzeDex(fo.name + '.dex')

        return apk, classes_dex, analysis

    def __androguard_open_apk(self, APK):
        """
        Method used to analyze an apk at the beginning of the execution
        it will also call load_specific_api.
        This method should be called only once per APK, as AnalyzeAPK
        from Androguard can take long time for the execution.

        :param APK: path of the apk to analyze
        :param class_name_to_analyze: class where to obtain the methods
        :return: None
        """
        Debug.log("analyzing %s file with androguard" % (APK))
        try:
            self.apk, self.classes_dex, self.analysis = self.__androguard_analyze_apk(
                APK)
        except Exception as e:
            Debug.warning("Error analyzing apk with androguard", e)
            self.permission_analysis = {
                "ERROR_TAG": "EXCEPTION",
                "FILE": APK,
                "ERROR_MESSAGE": str(e),
                "EXCEPTION_TYPE": str(type(e))
            }
            self.analysis_ok = False
            return

        api_level = self.apk.get_effective_target_sdk_version()
        Debug.log("Loading api-permission map for api level %d" % (api_level))
        # Change this after extracting new api levels
        if api_level > 29:
            Debug.log(
                "Api level greater than maximum supported (29), using 29 by default")
            api_level = 29
        elif api_level < 16:
            Debug.log(
                "Api level lower than minimum supported (16), using 16 by default")
            api_level = 16

        self.analysis.load_specific_api(api_level)

        self.analysis_ok = True
        return

    def __is_external_class(self, class_name):
        """
        Method to test if a class_name is one of the external
        classes or not (considered internal).

        :param class_name: name of the method to check if is external
        :return: boolean based on given class
        """
        for external_class in self.external_classes:
            if class_name == external_class.name:
                Debug.log("%s class is external" % (class_name))
                return True

        Debug.log("%s class is not external" % (class_name))
        return False

    def __get_method_objects(self, class_=""):
        """
        Given a class, get from the analysis object all the methods,
        this method changed in order to analyze all the methods from that
        class

        :param class_: name of the class where to search the method
        :return: List of MethodAnalysis object
        """

        # in other case, search manually the first method by class and name
        classes = list(self.analysis.get_classes())
        methods = []

        Debug.log("Checking for the presence of class %s" % (class_))

        for c in classes:
            if class_ == str(c.name):
                Debug.log("Class %s found in apk classes" % class_)
                methods = list(c.get_methods())
                break

        return methods

    def __get_method_object(self, class_="", method_="", descriptor=""):
        """
        Given a class and a method, get from analysis object the method
        object given as name. It is necessary to search by classes and
        method names.

        :param class_: name of the class where to search the method
        :param method_: name of the method to search
        :param descriptor: descriptor of the method, useful when we have
                           more than one method with the same name.
        :return: MethodAnalysis object
        """
        method_analysis = None
        # if descriptor is given, use it to search through androguard methods
        if descriptor is not None and descriptor != "":
            method_analysis = self.analysis.get_method_analysis_by_name(
                class_, method_, descriptor)

        if method_analysis is not None:
            return method_analysis

        # in other case, search manually the first method by class and name
        classes = list(self.analysis.get_classes())
        methods = []

        Debug.log("Checking for the presence of class %s and method %s" %
                  (class_, method_))

        for c in classes:
            if class_ == str(c.name):
                Debug.log("Class %s found in apk classes" % class_)
                methods = list(c.get_methods())
                break

        for method in methods:
            if method_ == str(method.name):
                if descriptor is None or len(descriptor) > 0:
                    Debug.log("Method %s found in the class" % method_)
                    return method
                elif descriptor == str(method.descriptor):
                    Debug.log("Method %s found in the class" % method_)
                    return method

        Debug.log("Method not found returning NULL")
        return None

    def __extract_class_and_method_names(self, complete_name):
        """
        Extract the class name, and the method name from a complete
        name given as the parameter of an "invoke" instruction.

        ...example:
            Ljava/lang/Object;-><init>()V

            We should return from here two strings:
                Ljava/lang/Object   <--- class name
                <init>              <--- method name

        :param complete_name: name where to extract information from
        :return: class and method names
        """
        class_regex = re.compile("(L.+)(?=->)")
        method_regex = re.compile("(?=(->)).+(?=\()")
        class_name = ""
        method_name = ""

        if class_regex.search(complete_name):
            class_name = class_regex.search(complete_name).group()

        if method_regex.search(complete_name):
            method_name = method_regex.search(
                complete_name).group().replace('->', '')

        Debug.log("Extracted class (%s) and method (%s)" %
                  (class_name, method_name))

        return class_name, method_name

    def __extract_class_method_and_descriptor_names(self, complete_name):
        """
        Extract the class name, and the method name from a complete
        name given as the parameter of an "invoke" instruction.

        ...example:
            Ljava/lang/Object;-><init>()V

            We should return from here two strings:
                Ljava/lang/Object   <--- class name
                <init>              <--- method name
                ()V                 <--- descriptor name

        :param complete_name: name where to extract information from
        :return: class, method and descriptor names
        """
        class_regex = re.compile("(L.+)(?=->)")
        method_regex = re.compile("(?=(->)).+(?=\()")
        class_name = ""
        method_name = ""
        descriptor_name = ""

        if class_regex.search(complete_name):
            class_name = class_regex.search(complete_name).group()

        if method_regex.search(complete_name):
            method_name = method_regex.search(
                complete_name).group().replace('->', '')

        if method_name:
            descriptor_name = complete_name.split('->' + method_name)[1]

        Debug.log("Extracted class (%s), method (%s) and descriptor (%s)" %
                  (class_name, method_name, descriptor_name))

        return class_name, method_name, descriptor_name

    def __analyze_method(self, methodAnalysis, depth, call_stack=[]):
        """
        Method to search for permissions given a method analysis object,
        if we find an API call, we will search its permission in Androguard
        and if the call is to internal function, recuversively will call
        analyze_method again with added value for depth.

        :param methodAnalysis: method analysis object to extract information.
        :param depth: depth of the analysis, given a constant depth analysis stop
        :return: list of permissions related to a method
        """

        local_methods_to_analyze = []

        if depth == self.MAX_DEPTH:
            return

        method = methodAnalysis.get_method()

        # some class is not recognized as external
        # by androguard, but the method is external
        if type(method) is ExternalMethod or 'ExternalMethod' in type(method).__name__:
            return

        for idx, ins in method.get_instructions_idx():
            #Debug.log("%08x:\t%x\t\t%s %s" % (idx, ins.get_op_value(), ins.get_name(), ins.get_output()))
            if "invoke" in ins.get_name():
                Debug.log("%08x:\t%x\t\t%s %s" % (
                    idx, ins.get_op_value(), ins.get_name(), ins.get_output()))

                class_name, method_name, descriptor_name = self.__extract_class_method_and_descriptor_names(
                    ins.get_output())
                # check possible errors
                if not class_name or class_name == "" or not method_name or method_name == "" or not descriptor_name or descriptor_name == "":
                    Debug.warning("Error retrieving class and method names", 1)
                    continue

                # check it was already analyzed
                if class_name+'->'+method_name+descriptor_name in self.analyzed_methods:
                    Debug.log("%s->%s%s already analyzed, going to next instruction" %
                              (class_name, method_name, descriptor_name))
                    continue

                # now check if class is external class or internal from the application
                # external, analyze permissions related
                if self.__is_external_class(class_name):
                    '''
                    Paths to classes (Lpackage/package/Class;) in:
                    https://github.com/Fare9/androguard/tree/master/androguard/core/api_specific_resources/api_permission_mappings
                    change from one SDK to another, but probably if we search only for class,
                    as this name doesn't usually change, we will be able to find permissions
                    associated to methods.
                    '''
                    list_of_methods = self.analysis.get_permissions_from_method(
                        ntpath.basename(class_name), method_name)

                    if list_of_methods and len(list_of_methods) > 0:
                        self.permission_analysis[class_name +
                                                 '->' + method_name] = list_of_methods
                        Debug.log("Permissions related to \"%s->%s\": %s" % (class_name,
                                                                             method_name, self.permission_analysis[class_name + '->' + method_name]))

                        Debug.analyst(
                            "==========================================")
                        Debug.analyst("Permissions related to \"%s->%s\": %s" % (
                            class_name, method_name, self.permission_analysis[class_name + '->' + method_name]))
                        # print the call stack
                        Debug.analyst("Call Stack (Depth of %d): " %
                                      (depth + 1))  # because it starts in 0
                        for call_ in call_stack:
                            Debug.analyst("%s ====>" % (call_))
                        Debug.analyst(
                            "%s" % (class_name+'->'+method_name+descriptor_name))
                        Debug.analyst(
                            "==========================================")
                        Debug.analyst("")

                    self.analyzed_methods.append(
                        class_name + '->' + method_name+descriptor_name)

                else:  # if internal method add to local_methods_to_analyze
                    if class_name + '->' + method_name + descriptor_name not in local_methods_to_analyze:
                        local_methods_to_analyze.append(
                            class_name + '->' + method_name + descriptor_name)
                        Debug.log("%s->%s%s added to later analysis" %
                                  (class_name, method_name, descriptor_name))

        # now go through each local_methods_to_analyze
        for local_method in local_methods_to_analyze:
            class_name, method_name, descriptor_name = self.__extract_class_method_and_descriptor_names(
                local_method)
            method_object = self.__get_method_object(
                class_name, method_name, descriptor_name)

            if method_object is None:
                continue
            # add it to analyzed methods, so avoid recursived calls
            self.analyzed_methods.append(local_method)
            Debug.log("Starting the analysis in method %s (depth of analysis = %d)!!!" % (
                local_method, depth+1))
            self.__analyze_method(method_object, depth+1, call_stack +
                                  [class_name + "->" + method_name + descriptor_name])

        # here just pray god everything worked properly and finished here

    def set_class_to_analyze(self, class_name_to_analyze=""):
        """
        Method to extract from androguard's analysis the external classes
        and method objects.
        This method has been created to avoid creating a PermissionTracer
        object each time a new class is given to analyze.

        :param class_name_to_analyze: class name to analyze
        :return:
        """
        self.__set_variables()

        self.class_name = class_name_to_analyze

        self.external_classes = list(self.analysis.get_external_classes())

        self.methods_objects_start = self.__get_method_objects(
            class_name_to_analyze)

        for method in self.methods_objects_start:
            Debug.log("Method to analyze %s->%s" %
                      (class_name_to_analyze, str(method.name)))

        if not self.methods_objects_start or len(self.methods_objects_start) == 0:
            Debug.warning("Error obtaining methods from %s" %
                          (self.class_name), 2)
        
        class_object = self.analysis.get_class_analysis(self.class_name)

        # initialize the string analysis object
        if class_object is not None:
            self.string_analyzer = StringAnalyzer(self.analysis, class_object, self.key_file)


    def analyze(self):
        Debug.log("Starting the analysis!!!")

        for method in self.methods_objects_start:
            Debug.log("Start analysis in method %s" % (str(method.name)))
            self.__analyze_method(
                method, 0, [self.class_name + "->" + str(method.name) + str(method.descriptor)])

        exposed_methods, data_provided, component_type = self.intent_filter_analyzer.analyze_class(
            self.class_name)

        self.permission_analysis = {"protected_apis": self.permission_analysis}
        self.permission_analysis.update(exposed_methods)
        self.permission_analysis.update(data_provided)
        self.permission_analysis.update(component_type)
        
        if self.key_file and self.string_analyzer is not None:
            string_analysis = {'string_analysis' : dict()}
            string_analysis['string_analysis'].update(self.string_analyzer.analyze_class_name())
            string_analysis['string_analysis'].update(self.string_analyzer.analyze_methods())
            string_analysis['string_analysis'].update(self.string_analyzer.analyze_fields())
            string_analysis['string_analysis'].update(self.string_analyzer.analyze_strings())
            self.permission_analysis.update(string_analysis)



def writeOutput(info):

    json_dump = json.dumps(info, indent=4, sort_keys=True)

    if FILE_OUTPUT:
        with open(FILE_NAME, 'w') as file_:
            file_.write(json_dump)
    else:
        print(json_dump)


def checkClassName(class_name):
    sanitized = class_name
    if '.' in class_name:
        sanitized = class_name.replace('.', '/')
    if class_name[0] != 'L':
        sanitized = 'L' + sanitized
    if class_name[-1] != ';':
        sanitized = sanitized + ';'
    return sanitized


def main():
    global DEBUG_FLAG
    global ANALYST_FLAG
    global WARNING_FLAG
    global ERROR_FLAG
    global FILE_OUTPUT
    global FILE_NAME

    permissionTracer = None
    strings_dump_file = None

    parser = argparse.ArgumentParser(
        description="PermissionTracer tool to extract aosp permissions from methods protected by custom permissions")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Show debug messages")
    parser.add_argument("-a", "--analyst", action="store_true",
                        help="Show interesting messages for analyst")
    parser.add_argument("-w", "--warning", action="store_true",
                        help="Show warning messages")
    parser.add_argument("-e", "--error", action="store_true",
                        help="Show error messages")
    parser.add_argument("-i", "--input", type=str,
                        help="APK to analyze", required=True)
    parser.add_argument("-m", "--md5hash", nargs='?', const='', type=str,
                        help="Specify the md5 hash of the apk (if file is given)")
    parser.add_argument("--class_name", type=str,
                        help="Class with the method to analyze (format package/package/class)", required=True)
    parser.add_argument("-o", "--output", type=str,
                        help="Specify output json file (stdout if not specified)")
    parser.add_argument("--dump-strings", type=str,
                        help="Dump the strings from the analyzed class")
    parser.add_argument("--key-file", type=str,
                        help="File with strings to search in analyzed class, one string per line")
    args = parser.parse_args()

    if args.debug:
        DEBUG_FLAG = True

    if args.analyst:
        ANALYST_FLAG = True

    if args.warning:
        WARNING_FLAG = True

    if args.error:
        ERROR_FLAG = True

    if args.output:
        FILE_OUTPUT = True
        FILE_NAME = args.output

    Debug.log("File to analyze specified by user \"%s\"" % args.input)
    Debug.log("Class to analyze \"%s\"" % args.class_name)

    class_name = args.class_name
    # Check if there are more than one class to analyze
    if ',' not in class_name:
        classes = [checkClassName(class_name)]
    else:
        classes = [checkClassName(item) for item in class_name.split(',')]

    results = dict()

    if args.key_file:
        permissionTracer = PermissionTracer(args.input, args.md5hash, args.key_file)
    else:    
        permissionTracer = PermissionTracer(args.input, args.md5hash)

    if args.dump_strings:
        strings_dump_file = open(args.dump_strings, 'w')

    for item in classes:
        # just if the analysis was correct
        if permissionTracer.analysis_ok:
            permissionTracer.set_class_to_analyze(item)
            permissionTracer.analyze()

            if args.dump_strings and permissionTracer.string_analyzer is not None:
                strings_dump_file.write("Class Name: " + permissionTracer.string_analyzer.class_name + '\n')
                for method in permissionTracer.string_analyzer.method_names:
                    strings_dump_file.write("Method Name: " + method + '\n')
                for field in permissionTracer.string_analyzer.field_names:
                    strings_dump_file.write("Field Name: " + field + '\n')
                for string in permissionTracer.string_analyzer.strings:
                    strings_dump_file.write("Raw String: " + string + '\n')

        results[item] = permissionTracer.permission_analysis
    
    if args.dump_strings:
        strings_dump_file.close()

    writeOutput(results)

    

if __name__ == '__main__':
    main()
