from volatility.obj import Object

explorer = Object('_EPROCESS', 0x80e91830, self.core.addrspace)
thread_list = explorer.ThreadListHead

list_head = list_entry = thread_list
list_entry = list_head.Flink

while(list_entry != list_head):
    

