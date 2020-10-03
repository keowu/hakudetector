#ifndef PEHEADERVISUALIZER_H
#define PEHEADERVISUALIZER_H

#include <QDialog>

namespace Ui {
class peheadervisualizer;
}

class peheadervisualizer : public QDialog
{
    Q_OBJECT

public:
    explicit peheadervisualizer(QWidget *parent = nullptr);
    ~peheadervisualizer();

private:
    Ui::peheadervisualizer *ui;
};

#endif // PEHEADERVISUALIZER_H
