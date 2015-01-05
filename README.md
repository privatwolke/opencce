This is opencce, a script that replicates part of the functionality
provided by the CCE (Citizen Card Encrypted) software by A-SIT.

Original here: https://joinup.ec.europa.eu/software/cce/description

This version uses only common open source utilities and produces containers
that can be decrypted successfully by the original CCE software.


# Use Cases
Bob wants to routinely encrypt his important data and uses two certificate
keys for this. One was exported from his e-card (citizen card), the private
key is always kept on the card. The other one was exported from a backup key
that he keeps as a hard copy in his bank vault. With opencce he can easily integrate
those two keys into his existing backup routine:
opencce encrypt -k ecardkey.pem -k backupkey.pem file1 file2 file3 file4

Hanna has to decrypt a large amount of data that was encrypted with a backup
key because she has lost or damaged her e-card. Since the private part of the
backup key can be transferred to a computer, she can use opencce to accomplish this.
opencce decrypt -k backupkeyring.p12 container1.cce
