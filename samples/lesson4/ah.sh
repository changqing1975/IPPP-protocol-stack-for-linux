ippp netns exec un0 ippp xfrm state add                     \
    src .#1.1.1.1/16                                        \
    dst .#1.1.1.2-1.1.1.2/8/0                               \
    proto ah                                                \
    direct out                                              \
    spi 0xfadc8b2a                                          \
    auth sha1 0xf594d69f00cfcb61aca00d5e2c25fd238f7c5ef1

ippp netns exec un0_1 ippp xfrm state add                   \
    src .#1.1.1.1/16                                        \
    dst .#1.1.1.2-1.1.1.2/8/0                               \
    proto ah                                                \
    direct in                                               \
    spi 0xfadc8b2a                                          \
    auth sha1 0xf594d69f00cfcb61aca00d5e2c25fd238f7c5ef1

ippp netns exec un0_1 ippp xfrm state add                   \
    src .#1.1.1.2-1.1.1.2/8                                 \
    dst .#1.1.1.1/16/0                                      \
    proto ah                                                \
    direct out                                              \
    spi 0xfadc8b2b                                          \
    auth sha1 0xf594d69f00cfcb61aca00d5e2c25fd238f7c5ef2

ippp netns exec un0 ippp xfrm state add                     \
    src .#1.1.1.2-1.1.1.2/8                                 \
    dst .#1.1.1.1/16/0                                      \
    proto ah                                                \
    direct in                                               \
    spi 0xfadc8b2b                                          \
    auth sha1 0xf594d69f00cfcb61aca00d5e2c25fd238f7c5ef2