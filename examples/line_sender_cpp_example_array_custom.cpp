#include <questdb/ingress/line_sender.hpp>
#include <iostream>
#include <vector>
#include <limits>
#include <stdexcept>

using namespace std::literals::string_view_literals;
using namespace questdb::ingress::literals;

struct ViewHolder {
    std::array<uintptr_t, 2> shape;
    std::array<intptr_t, 2> strides;
    const double* data;
    size_t size;
    questdb::ingress::array::strided_view<double, questdb::ingress::array::strides_mode::elements> view() const {
        return {2, shape.data(), strides.data(), data, size};
    }
};

namespace custom_array {
class Matrix {
public:
    Matrix(size_t rows, size_t cols)
        : _rows{rows},
          _cols{cols},
          _data(rows * cols, std::numeric_limits<double>::quiet_NaN()),
          _row_stride{cols},
          _col_stride{1} {}

    size_t rows() const { return _rows; }
    size_t cols() const { return _cols; }
    size_t row_stride() const { return _row_stride; }
    size_t col_stride() const { return _col_stride; }
    const double* data() const { return _data.data(); }
    size_t size() const { return _data.size(); }

    double get(size_t row, size_t col) const {
        return _data[index(row, col)];
    }

    void set(size_t row, size_t col, double value) {
        _data[index(row, col)] = value;
    }

    void transpose() {
        std::swap(_rows, _cols);
        std::swap(_row_stride, _col_stride);
    }

private:
    size_t _rows;
    size_t _cols;
    std::vector<double> _data;
    size_t _row_stride;
    size_t _col_stride;

    size_t index(size_t row, size_t col) const {
        if (row >= _rows || col >= _cols) {
            throw std::out_of_range("Matrix indices out of bounds");
        }
        return row * _row_stride + col * _col_stride;
    }
};

// Customization point for QuestDB array API (discovered via König lookup)
// If you need to support a 3rd party type, put this function in the namespace
// of the type in question or in the `questdb::ingress::array` namespace
inline auto to_array_view_state_impl(const Matrix& m) {
    return ViewHolder{
        {static_cast<uintptr_t>(m.rows()), static_cast<uintptr_t>(m.cols())},
        {static_cast<intptr_t>(m.row_stride()), static_cast<intptr_t>(m.col_stride())},
        m.data(),
        m.size()
    };
}
} // namespace custom_array

static bool array_example(std::string_view host, std::string_view port)
{
    using custom_array::Matrix;
    try {
        auto sender = questdb::ingress::line_sender::from_conf(
            "http::addr=" + std::string{host} + ":" + std::string{port} + ";");
        const auto table_name = "cpp_matrix_demo"_tn;
        const auto arr_col = "arr"_cn;

        Matrix m(2, 3);
        m.set(0, 0, 1.1); m.set(0, 1, 2.2); m.set(0, 2, 3.3);
        m.set(1, 0, 4.4); m.set(1, 1, 5.5); m.set(1, 2, 6.6);

        questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
        buffer.table(table_name)
            .column(arr_col, m)
            .at(questdb::ingress::timestamp_nanos::now());
        sender.flush(buffer);

        // Transpose and send again
        m.transpose();
        buffer.clear();
        buffer.table(table_name)
            .column(arr_col, m)
            .at(questdb::ingress::timestamp_nanos::now());
        sender.flush(buffer);
        return true;
    } catch (const questdb::ingress::line_sender_error& err) {
        std::cerr << "[ERROR] " << err.what() << std::endl;
        return false;
    }
}

int main(int argc, const char* argv[])
{
    auto host = "localhost"sv;
    if (argc >= 2)
        host = std::string_view{argv[1]};
    auto port = "9009"sv;
    if (argc >= 3)
        port = std::string_view{argv[2]};
    return !array_example(host, port);
}
