#include <questdb/ingress/column_sender.hpp>

void copy_borrowed_sender(questdb::ingress::borrowed_sender& sender)
{
    auto escaped = sender;
    (void)escaped;
}
