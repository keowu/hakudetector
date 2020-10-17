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
    void openFileFromAnotherScreen(QString pathfromanother);

private slots:
    void on_pushButton_clicked();

private:
    Ui::peheadervisualizer *ui;
};

#endif // PEHEADERVISUALIZER_H
