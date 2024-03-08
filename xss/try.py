def bubble_sort(self, arr, key):
    """
    Sorts a list of payloads (assumed to be dictionaries) in ascending order based on a specified key.

    Args:
        self: Reference to the current object (likely a class instance).
        arr (list): The list of payloads to be sorted.
        key (str): The key based on which sorting should be performed.

    Returns:
        list: The sorted list of payloads.
    """

    # Get the length of the payload list
    n = len(arr)

    # Traverse through all elements in the list
    for i in range(n):

        # Last i elements are already sorted, so we don't need to check them
        for j in range(0, n-i-1):

            # Compare the payloads based on the specified key
            if arr[j][key] > arr[j+1][key]:
                # Swap if the current payload is greater than the next one
                arr[j], arr[j+1] = arr[j+1], arr[j]

    # Return the sorted list of payloads
    return arr
