#ifndef ARPOPTIONS_H
#define ARPOPTIONS_H

typedef struct arp_options_s {
    std::string     replace_from;
    std::string     replace_to;
    bool            remove_encoding;
    bool            redirect_traffic;
    int             download_rate;
    int             upload_rate;
}               arp_options_t;

#endif // ARPOPTIONS_H
