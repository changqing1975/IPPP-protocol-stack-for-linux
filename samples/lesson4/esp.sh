ippp netns exec un0 ippp xfrm state add                             \
    src .#1.1.1.1/16                                                \
    dst .#1.1.1.2-1.1.1.2/8/0                                       \
    proto esp                                                       \
    direct out                                                      \
    spi 0xfadc8b2c                                                  \
    auth sha1 0xf594d69f00cfcb61aca00d5e2c25fd238f7c5ef1            \
    enc aes 0xe05064cee7c1803f8e901e9b6e732c35

ippp netns exec un0_1 ippp xfrm state add                           \
    src .#1.1.1.1/16                                                \
    dst .#1.1.1.2-1.1.1.2/8/0                                       \
    proto esp                                                       \
    direct in                                                       \
    spi 0xfadc8b2c                                                  \
    auth sha1 0xf594d69f00cfcb61aca00d5e2c25fd238f7c5ef1            \
    enc aes 0xe05064cee7c1803f8e901e9b6e732c35
