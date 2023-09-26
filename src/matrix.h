#ifndef MATRIX_H
#define MATRIX_H

#include <vector>
#include <iostream>
#include <iomanip>

template <typename T>
class matrix
{
protected:
    std::size_t n, d;
    std::vector<std::vector<T>> M;

public:
    // matrix();

    // empty matrix
    matrix() : n(0), d(0) {}

    //~matrix();

    //  rows * cols, all elements are initialized with the default constructor of T
    matrix(std::size_t rows, std::size_t cols) : n(0), d(0)
    {
        resize(rows, cols);
    }

    void clear()
    {
        n = d = 0;
        M.clear();
    }

    void resize(std::size_t rows, std::size_t cols)
    {
        std::size_t j;
        n = rows;
        d = cols;
        M.resize(d);
        for (j = 0; j < d; j++)
        {
            M[j].resize(n);
        }
    } // resize

    // return the number of rows
    int get_rows() const
    {
        return n;
    }

    // return the number of columns
    int get_cols() const
    {
        return d;
    }

    // a reference to the element (i, j)
    T &operator()(const std::size_t i, const std::size_t j) { return M[j][i]; }

    const T &operator()(const std::size_t i, const std::size_t j) const { return M[j][i]; }

    inline T &get(const std::size_t i, const std::size_t j) { return M[j][i]; }

    inline void set(const std::size_t i, const std::size_t j, const T a) { M[j][i] = a; }

    // the transpose of the matrix
    matrix<T> transpose() const
    {
        matrix<T> B(d, n);
        for (std::size_t i = 0; i < n; i++)
            for (std::size_t j = 0; j < d; j++)
                B(j, i) = M[j][i];
        return B;
    }

    // return the i-th row of the matrix; indices start from 0.
    std::vector<T> get_row(std::size_t i)
    {
        std::vector<T> v;
        v.resize(d);
        for (std::size_t j = 0; j < d; j++)
            v[j] = M[j][i];

        return v;
    }

    std::vector<T> get_row(std::size_t i) const
    {
        std::vector<T> v;
        v.resize(d);
        for (std::size_t j = 0; j < d; j++)
            v[j] = M[j][i];

        return v;
    }

    // return the last row of the matrix
    std::vector<T> get_last_row()
    {
        return get_row(n - 1);
    }

    std::vector<T> get_last_row() const
    {
        return get_row(n - 1);
    }

    // return the i-th column of the matrix; indices start from 0.
    std::vector<T> get_col(std::size_t j)
    {
        std::vector<T> v;
        v.resize(n);
        for (std::size_t i = 0; i < n; i++)
            v[i] = M[j][i];

        return v;
    }

    std::vector<T> get_col(std::size_t j) const
    {
        std::vector<T> v;
        v.resize(n);
        for (std::size_t i = 0; i < n; i++)
            v[i] = M[j][i];

        return v;
    }

    // return the last row of the matrix
    std::vector<T> get_last_col()
    {
        return get_col(d - 1);
    }

    std::vector<T> get_last_col() const
    {
        return get_col(d - 1);
    }

    void print(std::size_t rows = 6, std::size_t cols = 6)
    {
        size_t r = rows / 2;
        size_t c = cols / 2;

        for (size_t i = 0; i < r; i++)
        {
            std::cout << "    [";
            for (size_t j = 0; j < c; j++)
            {
                std::cout << std::setw(6) << std::right << std::right << M[j][i] << ",";
            }
            std::cout << std::setw(6) << std::right << std::right << "..."
                      << ",";
            for (size_t j = d - cols + c; j < d - 1; j++)
            {
                std::cout << std::setw(6) << std::right << std::right << M[j][i] << ",";
            }
            std::cout << std::setw(6) << std::right << std::right << M[d - 1][i] << "]" << std::endl;
        }

        std::cout << "    [";
        for (size_t j = 0; j < c; j++)
        {
            std::cout << std::right << std::setw(6) << std::right << "..."
                      << ",";
        }
        std::cout << std::setw(6) << std::right << std::right << "..."
                  << ",";
        for (size_t j = d - cols + c; j < d - 1; j++)
        {
            std::cout << std::setw(6) << std::right << std::right << "..."
                      << ",";
        }
        std::cout << std::setw(6) << std::right << std::right << "..."
                  << "]" << std::endl;

        for (size_t i = n - rows + r; i < n; i++)
        {
            std::cout << "    [";
            for (size_t j = 0; j < c; j++)
            {
                std::cout << std::setw(6) << std::right << std::right << M[j][i] << ",";
            }
            std::cout << std::setw(6) << std::right << std::right << "..."
                      << ",";
            for (size_t j = d - cols + c; j < d - 1; j++)
            {
                std::cout << std::setw(6) << std::right << std::right << M[j][i] << ",";
            }
            std::cout << std::setw(6) << std::right << std::right << M[d - 1][i] << "]" << std::endl;
        }
    }

}; // end of class matrix

#endif // matrix.h