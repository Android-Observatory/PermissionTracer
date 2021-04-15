# PermissionTracer

PermissionTracer is a tool developed with purpose of understanding what kind of component is protected by a given custom permission. Two different analysis are applied in the given class, being one of these analysis dependent on the type of component.

## Extraction of AOSP permissions related to API calls

PermissionTracer makes a tree analysis of each method from a given class, so for each internal method of a class the tool pases the *Smali* code to look for uses of the *invoke* instruction, in a *Breadth-first search* the tool classifies the methods as external or internal, for the former, the tool looks for its prototype in the mappings of APIs-AOSP Permissions from androguard to extract the corresponding AOSP permissions, if any, and the latter (internal methods) are pushed into a stack for recursively applying a *Depth-first search* analysis once the tool has analyzed the current method.

The process is represented in the next picture, the APIs are sorted by the order they are discovered, and the called methods are sorted by the order of how they are analyzed, at the top the tree has the method analyzed from the given component. The image also present how the API calls are extracted and checked with the API mappings:

![PermissionTracer Tree Analysis](permissionTracer_Tree.png)