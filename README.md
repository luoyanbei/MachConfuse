# MachConfuse
搜索macho中的汇编指令

在main.mm文件中找到main函数,指定 macho文件路径和存储路径，指定要搜索的汇编：

int main(int argc, const char * argv[])
{
    //原文件路径
    string sFilePath = "/path/to/TestSpace";
    //存储路径
    string sFilePath_save = "/path/to/TestSpace_2";
    
    //将要搜索的汇编指令
    vector<string> svc_asm_vec = {"movz x0,#0x1f", "movz x1,#0", "movz x2,#0", "movz x3,#0", "movz w16,#0x1a", "svc #0x80"};

    vector<string> svc_asm_vec_2 = {"svc #0x80"};
    
    uint64_t file_size = FileGetSize((char*)sFilePath.c_str());//计算文件大小
    void *file_buf = gain_fileBuf(sFilePath.c_str());//加载文件到内存
    //搜索到的"svc #0x80"的地址
    vector<uint64_t> addr_arry = search_svc_from_asm(file_buf, svc_asm_vec);
    
    if(addr_arry.size()>0){
        void * file_buf_save = alter_svc_to_nop(file_buf, addr_arry[0]);//修改第一个svc为nop
        save_buf_to_file(file_buf_save, file_size, sFilePath_save);//存储修改后的二进制到本地文件
    }
    
    return 0;
}
