from typing import Any, Literal

table_format = Literal['text', 'markdown', 'html']


def generate_table(data: list[list[Any]], columns: list[str],
                   right_adj_col: list[str] = [],
                   format: table_format = 'markdown') -> str:
    if format == 'html':
        return generate_html_table(data, columns, right_adj_col)
    elif format == 'markdown':
        return generate_md_table(data, columns, right_adj_col)
    else:
        return generate_md_table(data, columns, right_adj_col).replace('|', '').replace(':', '-')


def generate_md_table(data: list[list[Any]], columns: list[str], right_adj_col: list[str] = []) -> str:
    column_widths = [max(len(str(item)) for item in column) for column in zip(*([columns] + data))]

    table = ''

    formatted_row = ' | '.join(f"{str(item):<{column_widths[i]}}" for i, item in enumerate(columns))
    table += '| ' + formatted_row + ' |\n'

    table += '|' + '|'.join('-' * width + '-:' if c in right_adj_col else ':-' + '-' * width for width, c in zip(column_widths, columns)) + '|\n'

    for row in data:
        formatted_row = ''
        for i, item in enumerate(row):
            if columns[i] in right_adj_col:
                formatted_row += f"| {str(item):>{column_widths[i]}} "
            else:
                formatted_row += f"| {str(item):<{column_widths[i]}} "
        table += formatted_row + "|\n"

    return table


def generate_html_table(data: list[list[Any]], columns: list[str], right_adj_col: list[str] = []) -> str:
    table_html = "<table border='1'>\n"

    table_html += "<thead>\n<tr>\n"
    for column in columns:
        table_html += f"  <th style='text-align:left'>{column}</th>\n"
    table_html += "</tr>\n</thead>\n"

    table_html += "<tbody>\n"
    for row in data:
        table_html += "<tr>\n"
        for i, item in enumerate(row):
            if columns[i] in right_adj_col:
                table_html += f"  <td style='text-align:right'>{item}</td>\n"
            else:
                table_html += f"  <td style='text-align:left'>{item}</td>\n"
        table_html += "</tr>\n"
    table_html += "</tbody>\n"

    table_html += "</table>\n"

    return table_html
