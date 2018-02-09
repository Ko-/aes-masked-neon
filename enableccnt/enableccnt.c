#include <linux/module.h>
#include <linux/kernel.h>

static void enable_ccnt_read(void* data)
{
  // WRITE PMUSERENR = 1
  asm volatile ("mcr p15, 0, %0, c9, c14, 0\n\t" : : "r" (1));
}

int init_module()
{
  on_each_cpu(enable_ccnt_read, NULL, 1);
  return 0;
}

void cleanup_module()
{
}

MODULE_LICENSE("GPL");
