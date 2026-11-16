// Consumers that vendor the headers may put only include/questdb/ingress on
// the include path: the line_sender headers must reach their dependencies
// through relative includes alone.
#include "line_sender.h"
#include "line_sender.hpp"

int main()
{
    return 0;
}
