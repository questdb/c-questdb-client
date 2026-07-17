#include <questdb/ingress/qwp_sender.hpp>

qwp_sender* escape_raw_sender(questdb::ingress::sender_view& sender)
{
    return sender.c_ptr();
}
