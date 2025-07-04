### Oops message in `faulty` driver

Writing to the `faulty` device caused a kernel panic, booting the Linux host. The following message was displayed:

> Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000

The call trace indicated that the error occurred 8 bytes into the function `faulty_write`.

