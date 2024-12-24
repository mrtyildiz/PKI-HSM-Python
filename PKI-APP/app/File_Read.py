import os

ROOT_Dir = "/app/"
CRT_file = ROOT_Dir+"CRT/"
CSR_File = ROOT_Dir+"CSR/"
Upload_Dir = ROOT_Dir+"uploads/"
def Read_File_Func2(TypeCSR,csr_fileName,CompanyName):
    print(TypeCSR)
    CSR_File = ROOT_Dir+"CSR/"+str(CompanyName)+"/"+str(csr_fileName)
    with open(CSR_File, 'r') as f:
        csr_data = f.read()
        return csr_data

def Read_File_Func(TypeFile,FileName):
    if TypeFile == "CRT":
        crt_file = CRT_file + FileName + ".crt"
        with open(crt_file, 'r') as f:
            crt_data = f.read()
        return crt_data
    elif TypeFile == "uploads":
        csr_file = Upload_Dir + FileName
        with open(csr_file, 'r') as f:
            csr_data = f.read()
        return csr_data
    
    elif TypeFile == "CSR":
        csr_file = Upload_Dir + FileName
        with open(csr_file, 'r') as f:
            csr_data = f.read()
        return csr_data
    else:
        return False

#TypeF = "uploads"
#FileName = "procenne.com.csr"
#a = Read_File_Func(TypeF,FileName)
#print(a)