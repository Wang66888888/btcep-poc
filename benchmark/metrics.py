import csv
import os


RESULT_DIR = "results"


def save_result(
    filename,
    data
):

    os.makedirs(
        RESULT_DIR,
        exist_ok=True
    )


    path = os.path.join(
        RESULT_DIR,
        filename
    )


    exists = os.path.exists(path)


    with open(
        path,
        "a",
        newline=""
    ) as f:


        writer = csv.DictWriter(
            f,
            fieldnames=data.keys()
        )


        if not exists:

            writer.writeheader()


        writer.writerow(data)


    return path
