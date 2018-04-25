# IDBAutoMarkup
This script marks up an IDA Pro IDB with some comments that are helpful for malware reverse engineers when starting work on a sample.

It's primary two functions are the following:

(1) It attempts to trace usage of noteworthy APIs throughout the malware and writes comments to the IDB accordingly.
(2) It counts the number of xref's to all user functions and writes comments to the IDB accordingly.

Example output:

![Example output](https://raw.githubusercontent.com/nwshenk55/IDBAutoMarkup/master/IDA_MarkupScript_1.png)
