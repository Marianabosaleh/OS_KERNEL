#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/semaphore.h>
#include <linux/ioctl.h>
#include <linux/device.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

static int encryption_key = 0;


#define DEVICE_NAME "mychardev"
#define CLASS_NAME "mycharclass"

static int majorNumber;
static struct class *mycharClass = NULL;
static struct device *mycharDevice = NULL;

#define MYCHAR_IOC_MAGIC 'k'

#define SET_ENCRYPTION_KEY _IOW(MYCHAR_IOC_MAGIC, 0, int)
#define GET_ENCRYPTION_KEY _IOR(MYCHAR_IOC_MAGIC, 1, int)

static char *encrypted_data = NULL;              // Encrypted data storage
static struct rw_semaphore mychar_sem;           // Semaphore to control access to shared data

struct page_node {
    struct list_head list;
    char *data;
};

LIST_HEAD(page_list);


static int mychar_open(struct inode *inodep, struct file *filep)
{
    return 0;
}

static int mychar_release(struct inode *inodep, struct file *filep)
{
    return 0;
}

static ssize_t mychar_read(struct file *filep, char *buffer, size_t len, loff_t *offset)
{
    ssize_t bytes_read = 0;

    // Copy the encrypted data to the user buffer
    if (*offset < PAGE_SIZE)
    {
        bytes_read = (len < (PAGE_SIZE - *offset)) ? len : (PAGE_SIZE - *offset);
        if (copy_to_user(buffer, encrypted_data + *offset, bytes_read) != 0)
        {
            return -EFAULT;
        }
        *offset += bytes_read;
    }

    return bytes_read;
}

static ssize_t mychar_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{
  
    ssize_t bytes_written = 0;

    // Encrypt the input data with the key and store it in the encrypted_data buffer
    if (*offset < PAGE_SIZE)
    {
        size_t bytes_to_write = (len < (PAGE_SIZE - *offset)) ? len : (PAGE_SIZE - *offset);
        if (copy_from_user(encrypted_data + *offset, buffer, bytes_to_write) != 0)
        {
            return -EFAULT;
        }

        // Perform XOR encryption on the data
        int i;
        for (i = 0; i < bytes_to_write; i++)
        {
            encrypted_data[*offset + i] ^= encryption_key;
        }

        *offset += bytes_to_write;
        bytes_written = bytes_to_write;
    }

    return bytes_written;
}

static int mychar_seq_show(struct seq_file *m, void *v)
{
    // Lock access to the encrypted data
    down_read(&mychar_sem);

    // Print the encrypted data to the sequence file
    seq_printf(m, "%s\n", encrypted_data);

    // Unlock access to the encrypted data
    up_read(&mychar_sem);

    return 0;
}

static long mychar_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
    int retval = 0;

    // Lock access to the encryption key
    down_write(&mychar_sem);

    switch (cmd)
    {
    case SET_ENCRYPTION_KEY:
    {
        int new_encryption_key;
        if (copy_from_user(&new_encryption_key, (int __user *)arg, sizeof(int)) != 0)
        {
            retval = -EFAULT;
            break;
        }

        // Decrypt the data with the old key
        int i;
        for (i = 0; i < PAGE_SIZE; i++)
        {
            encrypted_data[i] ^= encryption_key; // Use encryption_key instead of old_encryption_key
        }

        // Encrypt the data with the new key
        for (i = 0; i < PAGE_SIZE; i++)
        {
            encrypted_data[i] ^= new_encryption_key;
        }

        encryption_key = new_encryption_key; // Set the new encryption_key
        break;
    }

    case GET_ENCRYPTION_KEY:
        if (copy_to_user((int __user *)arg, &encryption_key, sizeof(int)) != 0)
        {
            retval = -EFAULT;
        }
        break;

    default:
        retval = -EINVAL;
        break;
    }

    // Unlock access to the encryption key
    up_write(&mychar_sem);

    return retval;
}


static struct file_operations fops = {
    .open = mychar_open,
    .release = mychar_release,
    .read = mychar_read,
    .write = mychar_write,
    .unlocked_ioctl = mychar_ioctl,
};

static int __init mychar_init(void)
{
    printk(KERN_INFO "Initializing the MyChar LKM\n");

    // Initialize the semaphore
    init_rwsem(&mychar_sem);

    // Allocate memory for the encrypted_data buffer
    encrypted_data = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!encrypted_data)
    {
        printk(KERN_ALERT "MyChar failed to allocate memory\n");
        return -ENOMEM;
    }

    // Dynamically allocate a major number
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber < 0)
    {
        printk(KERN_ALERT "MyChar failed to register a major number\n");
        kfree(encrypted_data);
        return majorNumber;
    }
    printk(KERN_INFO "MyChar registered correctly with major number %d\n", majorNumber);

    // Register the device class
    mycharClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(mycharClass))
    {
        unregister_chrdev(majorNumber, DEVICE_NAME);
        kfree(encrypted_data);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(mycharClass);
    }
    printk(KERN_INFO "MyChar device class registered correctly\n");

    // Register the device driver
    mycharDevice = device_create(mycharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(mycharDevice))
    {
        class_destroy(mycharClass);
        unregister_chrdev(majorNumber, DEVICE_NAME);
        kfree(encrypted_data);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(mycharDevice);
    }
    printk(KERN_INFO "MyChar device class created correctly\n");
    return 0;
}

static void __exit mychar_exit(void)
{
    device_destroy(mycharClass, MKDEV(majorNumber, 0));
    class_unregister(mycharClass);
    class_destroy(mycharClass);
    unregister_chrdev(majorNumber, DEVICE_NAME);
    kfree(encrypted_data);
    printk(KERN_INFO "MyChar: Goodbye from the LKM!\n");
}

module_init(mychar_init);
module_exit(mychar_exit);

