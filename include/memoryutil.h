#ifndef MEMORYUTIL_H
#define MEMORYUTIL_H

void    *memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen)
{
    int needle_first;
    const void *p = haystack;
    size_t plen = hlen;

    if (!nlen)
        return NULL;

    needle_first = *(unsigned char *)needle;

    while (plen >= nlen && (p = memchr(p, needle_first, plen - nlen + 1)))
    {
        if (!memcmp(p, needle, nlen))
            return (void *)p;

        p = ((char *) p) + 1;
        plen = hlen - (((char *) p) - (char *) haystack);
    }

    return NULL;
}

void DumpHex(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;

    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        //qDebug("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            //qDebug(" ");
            if ((i+1) % 16 == 0) {
                qDebug("|  %s ", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    //qDebug(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    //qDebug("   ");
                }
                qDebug("|  %s ", ascii);
            }
        }
    }
}

#endif // MEMORYUTIL_H
